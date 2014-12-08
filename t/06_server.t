use strict;
use warnings;
use Test::More;
use lib 't/lib';
use TLSTest;
use AnyEvent::Socket;
use AnyEvent::Handle;

#use Data::Dumper::Concise;

BEGIN {
    use_ok 'Protocol::TLS::Server';
}

new_ok 'Protocol::TLS::Server',
  [ cert_file => 't/test.crt', key_file => 't/test.key' ];

# openssl s_client -connect 127.0.0.1:4443 -cipher NULL-SHA -debug

subtest 'handshake' => sub {
    my $cv = AE::cv;
    my $a = AE::timer 4, 0, sub { $cv->send };

    my $server = Protocol::TLS::Server->new(
        version   => 'TLSv12',
        cert_file => 't/test.crt',
        key_file  => 't/test.key',
    );

    tcp_server undef, 4443, sub {
        my ( $fh, $host, $port ) = @_ or do {
            print STDERR "Client error \n";
            $cv->send;
            return;
        };

        my $con = $server->new_connection(
            on_handshake_finish => sub {
                my ($tls) = @_;
            },
            on_data => sub {
                my ( $tls, $data ) = @_;
                $tls->send($data);
                $tls->close;
            }
        );

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

                #print Dumper $server->{ctx};
                $cv->send;
            },
        );
        $h->on_read(
            sub {
                my $handle = shift;
                $con->feed( $handle->{rbuf} );
                $handle->{rbuf} = '';
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
    $cv->recv;
    pass;
};
done_testing;
