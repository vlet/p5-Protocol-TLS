package Protocol::TLS::Context;
use 5.008001;
use strict;
use warnings;
use Carp;
use Protocol::TLS::Trace qw(tracer);
use Protocol::TLS::RecordLayer;
use Protocol::TLS::Extension;
use Protocol::TLS::Crypto;
use Protocol::TLS::Constants
  qw(:end_types :state_types :alert_types :alert_desc :versions
  :c_types :hs_types is_tls_version cipher_type const_name);

# Mixin
our @ISA = qw(Protocol::TLS::RecordLayer Protocol::TLS::Extension);

my %sp = (
    connectionEnd       => undef,      # CLIENT, SERVER
    PRFAlgorithm        => undef,      # tls_prf_sha256
    BulkCipherAlgorithm => undef,      # null, rc4, 3des, aes
    CipherType          => undef,      # stream, block, aead
    enc_key_length      => undef,
    block_length        => undef,
    fixed_iv_length     => undef,
    record_iv_length    => undef,
    MACAlgorithm        => undef,      # sha1, sha256
    mac_length          => undef,
    mac_key_length      => undef,
    CompressionMethod   => undef,      # null
    master_secret       => ' ' x 48,
    client_random       => ' ' x 32,
    server_random       => ' ' x 32,
);

my %kb = (
    client_write_MAC_key        => undef,
    server_write_MAC_key        => undef,
    client_write_encryption_key => undef,
    server_write_encryption_key => undef,
    client_write_IV             => undef,
    server_write_IV             => undef,
);

sub new {
    my ( $class, %args ) = @_;

    my $self = bless {
        crypto  => Protocol::TLS::Crypto->new,
        pending => {
            securityParameters => {%sp},
            key_block          => {%kb},
            tls_version        => undef,
            session_id         => undef,
            cipher             => undef,
            hs_messages        => [],
        },
        current_decode => {},
        current_encode => {},
        session_id     => undef,
        tls_version    => undef,
        seq_read       => 0,            # 2^64-1
        seq_write      => 0,            # 2^64-1
        queue          => [],
        state          => STATE_IDLE,
    }, $class;
    $self->load_extensions('ServerName');

    croak "Connection end type must be specified: CLIENT or SERVER"
      unless exists $args{type}
      && ( $args{type} == CLIENT
        || $args{type} == SERVER );
    $self->{pending}->{securityParameters}->{connectionEnd} = $args{type};
    $self->{pending}->{securityParameters}
      ->{ $args{type} == SERVER ? 'server_random' : 'client_random' } =
      pack( 'N', time ) . $self->crypto->random(28);
    $self;
}

# Crypto backend object
sub crypto {
    shift->{crypto};
}

sub error {
    my $self = shift;
    tracer->debug("called error: @_\n");
    if ( @_ && !$self->{shutdown} ) {
        $self->{error} = shift;
        $self->{on_error}->( $self->{error} ) if exists $self->{on_error};
        $self->finish;
    }
    $self->{error};
}

sub finish {
    my $self = shift;
    $self->enqueue( [ CTYPE_ALERT, FATAL, $self->{error} ] )
      unless $self->shutdown;
    $self->shutdown(1);
}

sub close {
    my $self = shift;
    $self->enqueue( [ CTYPE_ALERT, FATAL, CLOSE_NOTIFY ] )
      unless $self->shutdown;
    $self->shutdown(1);
}

sub shutdown {
    my $self = shift;
    $self->{shutdown} = shift if @_;
    $self->{shutdown};
}

sub enqueue {
    my ( $self, @records ) = @_;
    for (@records) {
        tracer->debug(
                "enqueue "
              . const_name( 'c_types', $_->[0] )
              . (
                $_->[0] == CTYPE_HANDSHAKE
                ? "/" . const_name( 'hs_types', $_->[1] )
                : ''
              )
              . "\n"
        );
        push @{ $self->{queue} }, $self->record_encode( TLS_v12, @$_ );
        $self->state_machine( 'send', $_->[0],
            $_->[0] == CTYPE_HANDSHAKE ? $_->[1] : () );
    }
}

sub dequeue {
    my $self = shift;
    shift @{ $self->{queue} };
}

sub application_data {
    my ( $ctx, $buf_ref, $buf_offset, $length ) = @_;
    if ( exists $ctx->{on_data} && $ctx->state == STATE_OPEN ) {
        $ctx->{on_data}->( $ctx, substr $$buf_ref, $buf_offset, $length );
    }
    $length;
}

sub send {
    my ( $ctx, $data ) = @_;
    if ( $ctx->state == STATE_OPEN ) {
        $ctx->enqueue( [ CTYPE_APPLICATION_DATA, $data ] );
    }
}

sub state_machine {
    my ( $ctx, $action, $c_type, $hs_type ) = @_;
    my $prev_state = $ctx->state;

    if ( $c_type == CTYPE_ALERT ) {

    }
    elsif ( $c_type == CTYPE_APPLICATION_DATA ) {
        if ( $prev_state != STATE_OPEN ) {
            tracer->error("Handshake was not complete\n");
            $ctx->error(UNEXPECTED_MESSAGE);
        }
    }

    # IDLE state (waiting for ClientHello)
    elsif ( $prev_state == STATE_IDLE ) {
        if ( $c_type != CTYPE_HANDSHAKE && $hs_type != HSTYPE_CLIENT_HELLO ) {
            tracer->error("Only ClientHello allowed in IDLE state\n");
            $ctx->error(UNEXPECTED_MESSAGE);
        }
        else {
            $ctx->state(STATE_HS_START);
        }
    }

    # Start Handshake (waiting for ServerHello)
    elsif ( $prev_state == STATE_HS_START ) {
        if ( $c_type != CTYPE_HANDSHAKE && $hs_type != HSTYPE_SERVER_HELLO ) {
            tracer->error(
                "Only ServerHello allowed at Handshake Start state\n");
            $ctx->error(UNEXPECTED_MESSAGE);
        }
        elsif ( $ctx->{session_id} eq $ctx->{pending}->{session_id} ) {
            $ctx->state(STATE_SESS_RESUME);
        }
        else {
            $ctx->state(STATE_SESS_NEW);
        }
    }

    elsif ( $prev_state == STATE_SESS_RESUME ) {
        if ( $c_type == CTYPE_HANDSHAKE ) {
            if ( $hs_type == HSTYPE_FINISHED ) {

                #$ctx->state( STATE_HS_FULL )
            }
        }
        elsif ( $c_type == CTYPE_CHANGE_CIPHER_SPEC ) {
            $ctx->change_cipher_spec($action);
        }
        else {
            tracer->error("Unexpected Handshake type\n");
            $ctx->error(UNEXPECTED_MESSAGE);
        }
    }

    # STATE_SESS_NEW
    elsif ( $prev_state == STATE_SESS_NEW ) {
        if ( $c_type == CTYPE_HANDSHAKE ) {
            if ( $hs_type == HSTYPE_SERVER_HELLO_DONE ) {
                $ctx->state(STATE_HS_HALF);
            }
        }
        else {
            tracer->error("Unexpected Handshake type\n");
            $ctx->error(UNEXPECTED_MESSAGE);
        }
    }

    # STATE_HS_HALF
    elsif ( $prev_state == STATE_HS_HALF ) {
        if ( $c_type == CTYPE_HANDSHAKE ) {
            if ( $hs_type == HSTYPE_FINISHED ) {
                $ctx->state(STATE_HS_FULL);
            }
        }
        elsif ( $c_type == CTYPE_CHANGE_CIPHER_SPEC ) {
            $ctx->change_cipher_spec($action);
        }
        else {
            tracer->error("Unexpected Handshake type\n");
            $ctx->error(UNEXPECTED_MESSAGE);
        }
    }

    # STATE_HS_FULL
    elsif ( $prev_state == STATE_HS_FULL ) {
        if ( $c_type == CTYPE_HANDSHAKE ) {
            if ( $hs_type == HSTYPE_FINISHED ) {
                $ctx->state(STATE_OPEN);
            }
        }
        elsif ( $c_type == CTYPE_CHANGE_CIPHER_SPEC ) {
            $ctx->change_cipher_spec($action);
        }
        else {
            tracer->error("Unexpected Handshake type\n");
            $ctx->error(UNEXPECTED_MESSAGE);
        }
    }

    # ReNegotiation
    elsif ( $prev_state == STATE_OPEN ) {

    }
}

sub generate_key_block {
    my $ctx = shift;
    tracer->debug("Generating key block\n");
    my $sp = $ctx->{pending}->{securityParameters};
    my $kb = $ctx->{pending}->{key_block};
    ( my $da, $sp->{BulkCipherAlgorithm}, $sp->{MACAlgorithm} ) =
      cipher_type( $ctx->{pending}->{cipher} );

    $sp->{mac_length} = $sp->{mac_key_length} =
        $sp->{MACAlgorithm} eq 'SHA'    ? 20
      : $sp->{MACAlgorithm} eq 'SHA256' ? 32
      : $sp->{MACAlgorithm} eq 'MD5'    ? 16
      :                                   0;

    (
        $sp->{CipherType},      $sp->{enc_key_length},
        $sp->{fixed_iv_length}, $sp->{block_length}
      )
      =
        $sp->{BulkCipherAlgorithm} eq 'AES_128_CBC'  ? ( 'block', 16, 16, 16 )
      : $sp->{BulkCipherAlgorithm} eq 'AES_256_CBC'  ? ( 'block', 32, 16, 16 )
      : $sp->{BulkCipherAlgorithm} eq '3DES_EDE_CBC' ? ( 'block', 24, 8,  8 )
      : $sp->{BulkCipherAlgorithm} eq 'RC4_128' ? ( 'stream', 16, 0, undef )
      :                                           ( 'stream', 0,  0, undef );

    (
        $kb->{client_write_MAC_key},
        $kb->{server_write_MAC_key},
        $kb->{client_write_encryption_key},
        $kb->{server_write_encryption_key},
        $kb->{client_write_IV},
        $kb->{server_write_IV}
      )
      = unpack sprintf(
        'a%i' x 6,
        ( $sp->{mac_key_length} ) x 2,
        ( $sp->{enc_key_length} ) x 2,
        ( $sp->{fixed_iv_length} ) x 2,
      ),
      $ctx->crypto->PRF(
        $sp->{master_secret},
        "key expansion",
        $sp->{server_random} . $sp->{client_random},
        $sp->{mac_key_length} * 2 +
          $sp->{enc_key_length} * 2 +
          $sp->{fixed_iv_length} * 2
      );

    ();
}

sub change_cipher_spec {
    my ( $ctx, $action ) = @_;
    tracer->debug("Apply cipher spec $action...\n");

    my $sp = $ctx->{pending}->{securityParameters};
    my $kb = $ctx->{pending}->{key_block};
    $ctx->generate_key_block unless defined $kb->{client_write_MAC_key};
    my $cur =
      $action eq 'recv' ? $ctx->{current_decode} : $ctx->{current_encode};
    $cur->{securityParameters}->{$_} = $sp->{$_} for keys %$sp;
    $cur->{key_block}->{$_}          = $kb->{$_} for keys %$kb;
}

sub state {
    my $ctx = shift;
    if (@_) {
        my $state = shift;
        $ctx->{on_change_state}->( $ctx, $ctx->{state}, $state )
          if exists $ctx->{on_change_state};

        $ctx->{state} = $state;

        # Exec callbacks for new state
        if ( exists $ctx->{cb} && exists $ctx->{cb}->{$state} ) {
            for my $cb ( @{ $ctx->{cb}->{$state} } ) {
                $cb->($ctx);
            }
        }
    }
    $ctx->{state};
}

sub state_cb {
    my ( $ctx, $state, $cb ) = @_;
    push @{ $ctx->{cb}->{$state} }, $cb;
}

sub validate_server_hello {
    my ( $ctx, %h ) = @_;
    my $tls_v = is_tls_version( $h{version} );
    my $p     = $ctx->{pending};
    if ( !defined $tls_v ) {
        tracer->error("peer's TLS version $h{version} not supported\n");
        return undef;
    }
    $p->{tls_version}                             = $tls_v;
    $p->{securityParameters}->{server_random}     = $h{random};
    $p->{session_id}                              = $h{session_id};
    $p->{securityParameters}->{CompressionMethod} = $h{compression};
    $p->{cipher}                                  = $h{cipher};
    1;
}

sub validate_client_hello {
    my ( $ctx, %h ) = @_;
    my $tls_v = is_tls_version( $h{version} );
    my $p     = $ctx->{pending};
    if ( !defined $tls_v ) {
        tracer->error("peer's TLS version $h{version} not supported\n");
        return undef;
    }
    $p->{tls_version}                             = $tls_v;
    $p->{securityParameters}->{client_random}     = $h{random};
    $p->{session_id}                              = $ctx->crypto->random(32);
    $p->{securityParameters}->{CompressionMethod} = $h{compression}->[0];

    # Choose first defined cipher
    for my $cipher ( @{ $h{ciphers} } ) {
        next unless cipher_type($cipher);
        $p->{cipher} = $cipher;
        last;
    }
    if ( !exists $p->{cipher} ) {
        tracer->error("peer's ciphers not supported\n");
        return undef;
    }
    1;
}

sub validate_client_key {
    my ( $ctx, $pkey ) = @_;
    my $p  = $ctx->{pending};
    my $sp = $p->{securityParameters};
    my ( $da, $ca, $mac ) = cipher_type( $p->{cipher} );

    if ( $da eq 'RSA' ) {
        my $preMasterSecret = $ctx->crypto->rsa_decrypt( $ctx->{key}, $pkey );

        $sp->{master_secret} = $ctx->crypto->PRF(
            $preMasterSecret,
            "master secret",
            $sp->{client_random} . $sp->{server_random}, 48
        );

    }
    else {
        die "not implemented";
    }

}

sub validate_finished {
    my ( $ctx, $message ) = @_;
    $ctx->{pending}->{finished} = $message;
}

1
