use strict;
use warnings;
use Test::More;
use lib 't/lib';
use TLSTest;
use AnyEvent::Socket;
use AnyEvent::Handle;

#use Data::Dumper::Concise;

BEGIN {
    use_ok 'Protocol::TLS::Client';
}

new_ok 'Protocol::TLS::Client';

# openssl s_server -accept 4443 -cert test.crt -key test.key -debug

subtest 'handshake' => sub {
    my $client = Protocol::TLS::Client->new( version => 'TLSv12', );

    my $cv = AE::cv;
    tcp_connect '127.0.0.1', 4443, sub {
        my $fh = shift or do {
            print "error: $!\n";
            $cv->send;
            return;
        };
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

        my $con = $client->new_connection(
            'example.com',
            on_handshake_finish => sub {
                my ($tls) = @_;
                $tls->send("test data\n");
            },
            on_data => sub {
                my ( $tls, $data ) = @_;
                like $data, qr/test/;
                $tls->close;
            }
        );

        while ( my $record = $con->next_record ) {
            $h->push_write($record);
        }

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
        ();
    };

    $cv->recv;
    pass;
};

done_testing;

