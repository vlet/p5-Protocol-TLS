package Protocol::TLS::RecordLayer;
use strict;
use warnings;
use Protocol::TLS::Trace qw(tracer);
use Protocol::TLS::Constants qw(is_tls_version :versions :c_types);
use Protocol::TLS::ChangeCipherSpec;
use Protocol::TLS::Handshake;
use Protocol::TLS::Alert;
use Protocol::TLS::Application;
use Protocol::TLS::Compression;
use Protocol::TLS::Protection;

my %content_types = (
    &CTYPE_CHANGE_CIPHER_SPEC => 'ChangeCipherSpec',
    &CTYPE_ALERT              => 'Alert',
    &CTYPE_HANDSHAKE          => 'Handshake',
    &CTYPE_APPLICATION_DATA   => 'Application',
);

my %decoder =
  map { $_ => \&{ 'Protocol::TLS::' . $content_types{$_} . '::decode' } }
  keys %content_types;

my %encoder =
  map { $_ => \&{ 'Protocol::TLS::' . $content_types{$_} . '::encode' } }
  keys %content_types;

sub record_decode {
    my ( $ctx, $buf_ref, $buf_offset ) = @_;
    return 0 if length($$buf_ref) - $buf_offset < 5;
    my ( $type, $version, $length ) = unpack "x${buf_offset}Cn2", $$buf_ref;

    if ( !is_tls_version($version) ) {
        tracer->debug(
            sprintf "Unsupported TLS version: %i.%i\n",
            int( $version / 256 ),
            $version % 256
        );

        # Unsupported TLS version
        $ctx->error();
        return undef;
    }

    # Unknown content type
    if ( !exists $content_types{$type} ) {
        tracer->debug("Unknown content type: $type\n");

        # Unknown content type
        $ctx->error();
        return undef;
    }

    return 0
      if length($$buf_ref) - $buf_offset - 5 - $length < 0;

    my $decrypted = Protocol::TLS::Protection::decode( $ctx, $type, $version,
        $buf_ref, $buf_offset + 5, $length );

    return undef unless defined $decrypted;

    my $decompressed = Protocol::TLS::Compression::decode( $ctx, \$decrypted, 0,
        length $decrypted );

    return undef unless defined $decompressed;

    return undef
      unless defined $decoder{$type}
      ->( $ctx, \$decompressed, 0, length $decompressed );

    return 5 + $length;
}

sub record_encode {
    my ( $ctx, $version, $type ) = splice @_, 0, 3;
    my $payload = Protocol::TLS::Protection::encode(
        $ctx, $version, $type,
        Protocol::TLS::Compression::encode(
            $ctx, $encoder{$type}->( $ctx, @_ )
        )
    );
    pack( 'Cn2', $type, $version, length $payload ) . $payload;
}

1
