package Protocol::TLS::Client;
use strict;
use warnings;
use Carp;
use Protocol::TLS::Trace qw(tracer bin2hex);
use Protocol::TLS::Context;
use Protocol::TLS::Connection;
use Protocol::TLS::Constants qw(const_name :state_types :end_types :c_types
  :versions :hs_types :ciphers cipher_type :alert_desc);

sub new {
    my ( $class, %opts ) = @_;
    my $self = bless { %opts, sid => {}, }, $class;
}

sub new_connection {
    my ( $self, $server_name, %opts ) = @_;
    croak "Specify server name of host" unless defined $server_name;

    my $ctx = Protocol::TLS::Context->new( type => CLIENT );
    my $con = Protocol::TLS::Connection->new($ctx);

    # Grab random session_id from cache (if exists)
    if ( exists $self->{sid}->{$server_name} ) {
        my $s   = $self->{sid}->{$server_name};
        my $sid = ( keys %$s )[0];

        $ctx->{proposed} = {
            session_id  => $sid,
            tls_version => $s->{$sid}->{tls_version},
            ciphers     => [ $s->{$sid}->{cipher} ],
            compression => [ $s->{$sid}->{compression} ],
        };
    }
    else {
        $ctx->{proposed} = {
            session_id => '',
            ciphers    => [
                TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_NULL_SHA256,
                TLS_RSA_WITH_NULL_SHA,
            ],
            tls_version => TLS_v12,
            compression => [0],
        };
    }

    if ( exists $opts{on_data} ) {
        $ctx->{on_data} = $opts{on_data};
    }

    $ctx->enqueue( [ CTYPE_HANDSHAKE, HSTYPE_CLIENT_HELLO, $ctx->{proposed} ] );

    $ctx->{on_change_state} = sub {
        my ( $ctx, $prev_state, $new_state ) = @_;
        tracer->debug( "State changed from "
              . const_name( 'state_types', $prev_state ) . " to "
              . const_name( 'state_types', $new_state ) );
    };

    # New session
    $ctx->state_cb(
        STATE_HS_HALF,
        sub {
            my $ctx    = shift;
            my $p      = $ctx->{pending};
            my $pro    = $ctx->{proposed};
            my $sp     = $p->{securityParameters};
            my $crypto = $ctx->crypto;

            # Server invalidate our session
            if ( $pro->{session_id} ne '' ) {
                delete $self->{sid}->{$server_name}->{ $pro->{session_id} };
            }

            my $pub_key = $crypto->cert_pubkey( $p->{cert}->[0] );

            my ( $da, $ca, $mac ) = cipher_type( $p->{cipher} );

            if ( $da eq 'RSA' ) {
                my $preMasterSecret =
                  pack( "n", $p->{tls_version} ) . $crypto->random(46);

                $sp->{master_secret} = $crypto->PRF(
                    $preMasterSecret,
                    "master secret",
                    $sp->{client_random} . $sp->{server_random}, 48
                );

                my $encoded =
                  $crypto->rsa_encrypt( $pub_key, $preMasterSecret );
                $ctx->enqueue(
                    [ CTYPE_HANDSHAKE, HSTYPE_CLIENT_KEY_EXCHANGE, $encoded ] );
            }
            else {
                die "not implemented";
            }

            $ctx->enqueue( [CTYPE_CHANGE_CIPHER_SPEC],
                [ CTYPE_HANDSHAKE, HSTYPE_FINISHED, $ctx->finished ] );
        }
    );

    $ctx->state_cb( STATE_SESS_RESUME,
        sub {
            my $ctx = shift;
            my $p   = $ctx->{pending};

            #my $pro    = $ctx->{proposed};
            my $sp = $p->{securityParameters};

            my $s = $self->{sid}->{$server_name}->{ $p->{session_id} };
            $p->{tls_version} = $s->{tls_version};
            $p->{cipher}      = $s->{cipher};
            $sp->{$_}         = $s->{securityParameters}->{$_}
              for keys %{ $s->{securityParameters} },

              tracer->debug( "Resume session: " . bin2hex( $p->{session_id} ) );
        }
    );

    $ctx->state_cb( STATE_HS_RESUME,
        sub {
            my $ctx = shift;
            $ctx->enqueue( [CTYPE_CHANGE_CIPHER_SPEC],
                [ CTYPE_HANDSHAKE, HSTYPE_FINISHED, $ctx->finished ] );
        }
    );

    $ctx->state_cb( STATE_OPEN,
        sub {
            my $ctx = shift;
            my $p   = $ctx->{pending};

            # add sid to client's cache
            $self->{sid}->{$server_name}->{ $p->{session_id} } =
              $ctx->copy_pending;
            $ctx->clear_pending;

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

Protocol::TLS::Client - pure Perl TLS Client

=head1 SYNOPSIS

    use Protocol::TLS::Client;

    # Create client object
    my $client = Protocol::TLS::Client->new();

    # You must create tcp connection yourself
    my $cv = AE::cv;
    tcp_connect 'example.com', 443, sub {
        my $fh = shift or do {
            warn "error: $!\n";
            $cv->send;
            return;
        };
        
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


        # Create new TLS-connection object
        my $con = $client->new_connection(

            # SERVER NAME (FQDN)
            'example.com',

            # Callback executed when TLS-handshake finished
            on_handshake_finish => sub {
                my ($tls) = @_;

                # Send some application data
                $tls->send("hi there\n");
            },
            
            # Callback executed when application data received
            on_data => sub {
                my ( $tls, $data ) = @_;
                print $data;
                
                # send close notify and close application level connection
                $tls->close;
            }
        );

        # Handshake start
        # Send TLS records to socket
        while ( my $record = $con->next_record ) {
            $h->push_write($record);
        }

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
        ();
    };

    # finish
    $cv->recv;

=head1 DESCRIPTION

Protocol::TLS::Client is TLS client library. It's intended to make TLS-client
implementations on top of your favorite event loop.

=head1 LICENSE

Copyright (C) Vladimir Lettiev.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Vladimir Lettiev E<lt>thecrux@gmail.comE<gt>

=cut

