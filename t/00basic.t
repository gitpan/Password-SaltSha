
use strict;
use warnings;

use Test::More;

use Password::SaltSha qw( salt salted_sha_pass salt_n_salted_sha_pass );

my $pw = "Test0";


like( 
    salt(), qr/^[[:ascii:]]{40}$/, 
    "salt() returns appropriate length, and reasonable characters." 
);


like(
    salted_sha_pass( $pw, salt() ), qr/^[[:xdigit:]]{64}$/,
    "salt_sha_pass() returns appropriate charaters and length."
);


is( 
    ref( salt_n_salted_sha_pass( $pw ) ), 'ARRAY', 
    "salt_n_salted_sha_pass() returns an array ref."
);

my $aref = salt_n_salted_sha_pass( $pw );

like(
    $aref->[0], qr/^[[:ascii:]]{40}$/,
    "salt_n_salted_sha_pass()->[0] returns appropriate salt string."
);

like(
    $aref->[1], qr/^[[:xdigit:]]{64}$/,
    "salt_n_salted_sha_pass()->[1] returns appropriate salted sha hex digits."
);


done_testing();
