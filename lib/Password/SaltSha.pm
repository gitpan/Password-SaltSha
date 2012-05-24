package Password::SaltSha;

use 5.006;
use strict;
use warnings;


our $VERSION   = '0.02';
our @ISA       = qw( Exporter );
our @EXPORT_OK = qw( generate_salted_sha validate_salted_sha );

use Crypt::SaltedHash;
use Math::Random::MT::Auto qw( irand );

use constant NUM_HEX_DIGITS => 32;  ## no critic (constant)
use constant NIBBLE         => 16;  ## no critic (constant)
use constant SALT_LENGTH    => 16;  ## no critic (constant)

sub generate_salted_sha {
    my $password = shift;
    my $rgen = Math::Random::MT::Auto->new();
    my $salt =
        join q{}, map {
            sprintf "%x", $rgen->irand % NIBBLE     # Magic number: 16.
        } 1 .. NUM_HEX_DIGITS;
    my $crypt = Crypt::SaltedHash->new(
        algorithm => 'SHA-512',
        salt      => "HEX{$salt}",
        salt_len  => SALT_LENGTH,
        
    );
    $crypt->add( $password );
    return $crypt->generate;
}

sub validate_salted_sha {
    my ( $hashed, $clear_pw ) = @_;
    my $crypt = Crypt::SaltedHash->new;
    return $crypt->validate( $hashed, $clear_pw, SALT_LENGTH );
}

1;

=head1 NAME

Password::SaltSha - Generate and validate SHA-512 passwords seasoned with 128
random bits of salt.

=head1 VERSION

Version 0.02


=head1 SYNOPSIS

Given a clear-text password, generates a SHA-512 hash seasoned with a random
128 bit salt.  The salt is bundled along with the hash for simple storage in
a user database.

Given salted hash created by the C<generate_salted_sha> function, validate
a clear-text password using C<validate_salted_sha>.

    use Password::SaltSha qw( 
        generate_salted_sha
        validate_salted_sha
    );

    my $salted_pass = generate_salted_sha( $password );
    print "We have a winner!\n"
        if( validate_salted_sha( $salted_pass, $password );


Use C<generate_salted_sha> to generate a password that has been hashed along
with randomly generated salt.  The password and salt are bundled together and
base-64 encoded for easy storage in a database of users.

Next, to validate a user, call C<validate_salted_sha>, passing it the
salted, hashed, base-64 encoded bundle as the first parameter, and the clear
text challenge password as the second.


=head1 EXPORT

Nothing exports by default.  May export C<generate_salted_sha> and
C<validate_salted_sha> if so specified in the usual manner:

    use Password::SaltSha qw( generate_salted_sha   validate_salted_sha );


=head1 SUBROUTINES/METHODS

=head2 generate_salted_sha

Pass in a clear-text password.  Internally, a 128 bit salt is randomly
generated.  That 128 bit salt is combined with the clear-text password, and
hashed using a SHA-512 algorithm.  The resulting hash is then bundled along
with the random hash in a base-64 encoded string that is suitable for storage
in a user database as 117 characters of ASCII text.

Each call to C<generate_salted_sha> uses a new random 128 bit salt.

=head2 validate_salted_sha

Pass the 117-character hash back as the first parameter, and a clear-text
challenge password as the second parameter.  Returns true if the clear-text
password validates against the salted and hashed password.


=head1 EXAMPLE

    my $user   = 'john doe';
    my $pass   = 'Super_Secret';
    my $bundle = generate_salted_sha( $pass );
    my $salt   = $credentials->[0];
    
    # Assuming you've got some 'store' function...
    store( $user, $bundle );
    
    # Later on...
    # Assuming you have get_login() and fetch() functions:
    my( $username, $clear_challenge_pass ) = get_login();
    my $stored_pass_hash = fetch( $user_login_name );

    if( validate_salted_sha( $stored_pass_hash, $clear_challenge_pass ) ) {
        print "$user_login_name: You are the winner!\n";
    }

Assuming you've filled in the blanks (created your versions of C<store()>, 
C<get_login()>, and C<fetch()>, and assuming the user has given you a valid
password for the given username, the output will be:

    john doe: You are the winner!

The typical use case will be to generate a salted and hashed password, store
the bundle in a database of users, and then later retrieve the hashed password
bundle to verify that the clear text password provided at some user
login validates against the encrypted one stored in the database.

It is safe (and normal operating procedure) to store the salt within a
database.  The salt plus a password hash cannot be used to reverse-engineer
original clear-text passwords.  However, a unique salt per user that is
hashed along with a clear text password does create a stronger password hash,
and is more effective against rainbow attacks than simply storing a hash based
entirely on just a password.

=head1 WHY?

Because I got tired of implementing something similar to this every time I 
build an application that uses logins, and because it's trickey enough to get
right that it's worth sticking with a tested implementation.

If you find it useful, that's nice too. ;)

=head1 DESCRIPTION

This module draws from the strength of two good modules:
Math::Random::MT::Auto, and Crypt::SaltedHash.

The salt generation routine uses a very good random number generator, provided
internally by Math::Random::MT::Auto.  This should be a better quality random
salt than the one provided internally by Crypt::SaltedHash.  However,
Crypt::SaltedHash does a very nice job of packaging the salted and hashed
password into a tidy bundle that is fit for storage as 117 characters of good
old ASCII text in a database.  By wrapping the strengths of those two modules
in a simple user interface with sane defaults, Password::SaltSha should be
a strong mechanism for password encryption and validation.

This module is effective in significantly I<increasing> the difficulty of
brute force or rainbow attacks against the SHA-512 hashed representation of a
password.  The 128 bit random salt just by itself provides 128 bits of
entropy.  Combined with any reasonable user password, the total entropy
increases to the point that brute force and rainbow attacks are extremely
difficult.

Keep in mind, all we're trying to do is make the original password harder to
guess.  Turning any password of any length into a password of original length
plus 128 bits of random noise makes for a very strong authentication
mechanism.

It should be noted that the salt used in protecting passwords of user accounts
on most operating systems has lower entropy, and no better random generator
than what is used in this module.  Using this module in a well-designed user
login should cross one item off the list of plausable attack vectors.

=head1 DEPENDENCIES

This module uses Math::Random::MT::Auto, which itself has the following
non-core dependencies: Exception::Class, Object::InsideOut.

This module also uses Crypt::SaltedHash, which has non-core dependencies of
Digest::SHA.

=head1 AUTHOR

David Oswald, C<< <davido at cpan.org> >>

=head1 BUGS AND LIMITATIONS

I would be interested in any comments that could lead to enhancing the
effectiveness of this module as a simple and robust security tool.  There are
no known limitations outside of what is already known of SHA-512, and 128 bit
random salt strategies.  But security is always an arms race.

Please report any bugs or feature requests to 
C<bug-password-saltsha at rt.cpan.org>, or through
the web interface at 
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Password-SaltSha>.  I will be
notified, and then you'll automatically be notified of progress on your bug as
I make changes.



=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Password::SaltSha


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Password-SaltSha>

=item * GitHub

L<https://github.com/daoswald/Password-SaltSha>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Password-SaltSha>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Password-SaltSha>

=item * Search CPAN

L<http://search.cpan.org/dist/Password-SaltSha/>

=back


=head1 ACKNOWLEDGEMENTS

Special thanks to M. Aaron Bossert for providing suggestions via the
Mojolicious email list that contributed to an improved API and the enhanced
effectiveness of this module.

And thanks to Ben van Staveren for his Mojolicious::Plugin::Authentication
module.  Password::SaltSha was originally conceived and designed as a simple
tool to plug into Mojolicious::Plugin::Authentication.

=head1 LICENSE AND COPYRIGHT

Copyright 2012 David Oswald.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut
