package Protocol::TLS::Server;
use strict;
use warnings;
use Carp;
use MIME::Base64;
use Protocol::TLS::Trace qw(tracer bin2hex);
use Protocol::TLS::Context;
use Protocol::TLS::Connection;
use Protocol::TLS::Constants
  qw(cipher_type const_name :versions :c_types :end_types :hs_types :state_types :alert_desc);

sub new {
    my ( $class, %opts ) = @_;
    my $self = bless {}, $class;
    $self->_load_cert( delete $opts{cert_file} );
    $self->_load_priv_key( delete $opts{key_file} );
    $self;
}

sub _load_cert {
    my ( $self, $file ) = @_;
    croak "specify cert_file path" unless defined $file;

    local $/;
    open my $fh, '<', $file or croak "opening cert_file error: $!";

    # TODO: multiple certs
    my ($cert) =
      ( <$fh> =~
/^-----BEGIN CERTIFICATE-----\r?\n(.+?\r?\n)-----END CERTIFICATE-----\r?\n/s
      );
    close $fh;
    croak "Certificate must be in PEM format" unless $cert;
    $self->{cert} = decode_base64($cert);
    ();
}

sub _load_priv_key {
    my ( $self, $file ) = @_;
    croak "specify key_file path" unless defined $file;

    local $/;
    open my $fh, '<', $file or croak "opening key_file error: $!";
    my ($key) =
      ( <$fh> =~
/^-----BEGIN RSA PRIVATE KEY-----\r?\n(.+?\r?\n)-----END RSA PRIVATE KEY-----\r?\n/s
      );
    close $fh;
    croak "Private key must be in PEM format" unless $key;
    $self->{key} = decode_base64($key);
    ();
}

sub new_connection {
    my ( $self, %opts ) = @_;
    my $ctx = Protocol::TLS::Context->new( type => SERVER );
    $ctx->{key}  = $self->{key};
    $ctx->{cert} = $self->{cert};
    my $con = Protocol::TLS::Connection->new($ctx);

    $ctx->{on_change_state} = sub {
        my ( $ctx, $prev_state, $new_state ) = @_;
        tracer->debug( "State changed from "
              . const_name( 'state_types', $prev_state ) . " to "
              . const_name( 'state_types', $new_state )
              . "\n" );
    };

    if ( exists $opts{on_data} ) {
        $ctx->{on_data} = $opts{on_data};
    }

    $ctx->state_cb(
        STATE_HS_START,
        sub {
            my $ctx    = shift;
            my $p      = $ctx->{pending};
            my $sp     = $p->{securityParameters};
            my $crypto = $ctx->crypto;

            $ctx->enqueue(
                [
                    CTYPE_HANDSHAKE,
                    HSTYPE_SERVER_HELLO,
                    {
                        server_random => $sp->{server_random},
                        session_id    => $p->{session_id},
                        cipher        => $p->{cipher},
                        compr         => $sp->{CompressionMethod}
                    }
                ],
                [ CTYPE_HANDSHAKE, HSTYPE_CERTIFICATE, $ctx->{cert} ],
                [ CTYPE_HANDSHAKE, HSTYPE_SERVER_HELLO_DONE ]
            );
        }
    );

    $ctx->state_cb(
        STATE_HS_FULL,
        sub {
            my $ctx    = shift;
            my $p      = $ctx->{pending};
            my $sp     = $p->{securityParameters};
            my $crypto = $ctx->crypto;

            my $mess = join( '', splice @{ $p->{hs_messages} }, 0, -1 );
            my $finished = $crypto->PRF(
                $sp->{master_secret},
                "client finished",
                $crypto->PRF_hash($mess), 12
            );
            tracer->debug( "finished: " . bin2hex($finished) . "\n" );
            tracer->debug(
                "finished client: " . bin2hex( $p->{finished} ) . "\n" );

            if ( $finished ne $p->{finished} ) {
                tracer->error("client finished not match");
                $ctx->error(HANDSHAKE_FAILURE);
                return;
            }

            $mess .= shift @{ $p->{hs_messages} };

            $ctx->enqueue(
                [CTYPE_CHANGE_CIPHER_SPEC],
                [
                    CTYPE_HANDSHAKE,
                    HSTYPE_FINISHED,
                    $crypto->PRF(
                        $sp->{master_secret},     "server finished",
                        $crypto->PRF_hash($mess), 12
                    )
                ]
            );

            # Handle callbacks
            if ( exists $opts{on_handshake_finish} ) {
                $opts{on_handshake_finish}->($ctx);
            }
        }
    );
    $con;
}

1
__END__

=encoding utf-8

=head1 NAME

Protocol::TLS::Server - pure Perl TLS Server

=head1 SYNOPSIS

    use Protocol::TLS::Server;

    # Create server object.
    # Load X509 certificate and private key
    my $server = Protocol::TLS::Server->new(
        cert_file => 'server.crt',
        key_file  => 'server.key',
    );

    # You must create tcp server yourself
    my $cv = AE::cv;
    tcp_server undef, 4443, sub {
        my ( $fh, $host, $port ) = @_ or do {
            warn "Client error\n";
            $cv->send;
            return;
        };

        # Create new TLS-connection object
        my $con = $server->new_connection(

            # Callback executed when TLS-handshake finished
            on_handshake_finish => sub {
                my ($tls) = @_;
                
                # send application data
                $tls->send("hello");
            },

            # Callback executed when application data received
            on_data => sub {
                my ( $tls, $data ) = @_;
                print $data;

                # send close notify and close application level connection
                $tls->close;
            }
        );

        # socket handling
        my $h;
        $h = AnyEvent::Handle->new(
            fh       => $fh,
            on_error => sub {
                $_[0]->destroy;
                print "connection error\n";
                $cv->send;
            },
            on_eof => sub {
                $h->destroy;
                print "that's all folks\n";
                $cv->send;
            },
        );

        # low level socket operations (read/write)
        $h->on_read(
            sub {
                my $handle = shift;

                # read TLS records from socket and put them to $con object
                $con->feed( $handle->{rbuf} );
                $handle->{rbuf} = '';

                # write TLS records to socket
                while ( my $record = $con->next_record ) {
                    $handle->push_write($record);
                }

                # Terminate connection if all done
                $handle->push_shutdown if $con->shutdown;
                ();
            }
        );
        ()
    };

    # finish
    $cv->recv;

=head1 DESCRIPTION

Protocol::TLS::Server is TLS server library. It's intended to make TLS-server
implementations on top of your favorite event loop.

=head1 LICENSE

Copyright (C) Vladimir Lettiev.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Vladimir Lettiev E<lt>thecrux@gmail.comE<gt>

=cut

