#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Password::SaltSha' ) || print "Bail out!\n";
}

diag( "Testing Password::SaltSha $Password::SaltSha::VERSION, Perl $], $^X" );
