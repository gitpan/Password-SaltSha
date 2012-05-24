
use strict;
use warnings;

use Test::More;

use Password::SaltSha qw( generate_salted_sha validate_salted_sha );

my $pw = "Test0";


like( 
    generate_salted_sha( $pw ), qr/^[[:ascii:]]{117}$/, 
    "generate_salted_sha() returns appropriate length, " .
    "and reasonable characters." 
);




my $result = generate_salted_sha( $pw );

is(
    validate_salted_sha( $result, $pw ), 1,
    "validate_salted_sha() validates our original password against the hash."
);


done_testing();
