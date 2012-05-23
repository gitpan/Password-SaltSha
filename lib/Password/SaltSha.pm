package Password::SaltSha;

use 5.012;
use strict;
use warnings;

use String::Random;
use Digest::SHA qw( sha256_hex );

our $VERSION   = '0.01';
our @ISA       = qw( Exporter );
our @EXPORT_OK = qw( salt salted_sha_pass salt_n_salted_sha_pass );

# Returns just a 'salt' guaranteed to be 40 ASCII characters long.
sub salt {
    my $rp   = String::Random->new();
    my $salt = $rp->randpattern( 's' x 40 );
    return $salt;
}

# Given params of $password, $salt:
# Returns just a SHA256 hex representation of the salted password.
# There will be 64 hex digits.
sub salted_sha_pass {
    my ( $password, $salt ) = @_;
    return sha256_hex( $password . $salt );
}

# Given param of $password:
# Salts the password, generates a SHA256 hex representation.
# Returns an array ref holding the plain salt, and the salted-sha'ed password.
sub salt_n_salted_sha_pass {
    my ($password) = @_;
    my $salt = salt();
    my $sha_pw = salted_sha_pass( $password, $salt );
    return [ $salt, $sha_pw ];
}

1;

=head1 NAME

Password::SaltSha - The great new Password::SaltSha!

=head1 VERSION

Version 0.01


=head1 SYNOPSIS

Creates a 40 ASCII character salt, and salts it into a password, returning
the SHA-256 (SHA2) salted password as a hex string.


    use Password::SaltSha qw( 
        salt 
        salted_sha_pass 
        salt_n_salted_sha_pass 
    );

    my $salt = salt();
    my $salted_pass = salted_sha_pass( $password, $salt );
    my $aref        = salt_n_salted_sha_pass( $password );
    $salt        = $aref->[0];
    $salted_pass = $aref->[1];


use C<salt> if all you want is a 40 ASCII character salt.  Use 
C<salt_n_salted_sha_pass> if you want to generate a salt and salted SHA-256
password pair, perhaps for storage in a user database.  Use C<salted_sha_pass>
if you want to check whether a given clear text password and salt match the
salted and SHA-256 encrypted one generated by C<salt_n_salted_sha_pass>.


=head1 EXPORT

Nothing exports by default.  May export C<salt>, C<salted_sha_pass>, and 
C<salt_n_salted_sha_pass>.

=head1 SUBROUTINES/METHODS

=head2 salt

Accepts no parameters.  Returns a string of 40 random ASCII characters
that are appropriate as salt.


=head2 salted_sha_pass

Accepts a password, and a salt string.  Returns a hex representation of a
SHA-256 (SHA2) that results from concatenating the password with the salt.
The result will be a 64 digit hex string.

This function is useful in checking to see whether a given salt and clear-text
password can be hashed to match some previously stored SHA2 hash.


=head2 salt_n_salted_sha_pass

Accepts only a password as a paramater.  Returns an array reference.  The
first field will be the random salt generated (40 ASCII characters).  The
second field will be the SHA-256 (SHA2) that resulted from concatenating
the password provided with the random salt generated.

This function is useful in generating (possibly for storage in a database of
users) a salt and a SHA-256 hash of the clear text password combined with the
salt.

=head1 EXAMPLE

    my $user = 'john doe';
    my $pass = 'Super_Secret';
    my $credentials = salt_n_salted_sha_pass( $pass );
    my $salt = $credentials->[0];
    my $pass_sha_as_hex = $credentials->[1];
    
    # Assuming you've got some 'store' function...
    store( $user, $salt, $pass_sha_as_hex );
    
    # Later on...
    my( $user_login_name, $user_clear_pass ) = get_login();
    my( $stored_salt, $stored_pass_hash ) = fetch( $user_login_name );
    if( salted_sha_pass( $user_clear_pass, $stored_salt ) eq
        $stored_pass_hash
    ) {
        print "$user_login_name: You are the winner!\n";
    }

Assuming you've filled in the blanks (created your versions of C<store()>, 
C<get_login()>, and C<fetch()>, and assuming the user has given you a valid
password for the given username, the output will be:

    john doe: You are the winner!

The typical use case will be to generate a salt and a hashed password, store
them in a database of users, and then later retrieve the salt and the
hashed password to verify that the clear text password provided at some user
login hashed together with the salt returns the same password hash that was
previously stored in the database.

It is safe (and normal operating procedure) to store the salt within a
database.  The salt plus a password hash cannot be used to reverse-engineer
original clear-text passwords.  However, a unique salt per user that is
hashed along with a clear text password does create a stronger password hash,
and is more effective against rainbow attacks than simply storing a hash based
entirely on just a password.

=head1 WHY?

Because I got tired of implementing something similar to this every time I 
build an application that uses logins.

If you find it useful, that's nice too. ;)

=head1 CAVEATS AND OPINION REGARDING EFFECTIVENESS

The salt generation routine is based on String::Random.  It is designed with
the philosophy that a pseudo-randomly generated salt of characters from the
list of C<[A-Za-z0-9./]>, which provides 60 bit-pattern possibilities per
character, in a length of 40 characters, will provide enough entropy to harden
just about any user supplied password.  The salt length of 40 was chosen
because that gives sufficient bits of entropy to seed even short passwords,
yielding near maximum entropy in the resulting SHA2-256 hash.

This module is effective in significantly I<increasing> the difficulty of
brute force or rainbow attacks against the SHA2-256 hashed representation of a
password.  I<But there are no guarantees as to B<how effective> > it is.

That said, it B<is> quite strong despite the fact that its strings are
generated using Perl's basic random number generator.  Why? Because SHA2-256
is already strong, and I<any> difficult to predict salt will provide even
better strength.  Despite these salts being generated using a simple approach,
they are "random enough" that when combined with a SHA2-256 hashing algorithm
and a user-supplied password, the amount of work necessary to break the hash
raises the bar beyond what is likely to be worthwhile for potential attackers.

Keep in mind, all we're trying to do is make the original password harder to
guess.  Turning any password of any length into a password of original length
plus forty pseudo-random digits of sixty possible characters is very effective
in that regard.

It should be noted that the salt used in protecting passwords of user accounts
on most operating systems has lower entropy, and no better random generator
than what is used in this module.  Using this module in a well-designed user
login should cross one item off the list of plausable attack vectors.


=head1 AUTHOR

David Oswald, C<< <davido at cpan.org> >>

=head1 BUGS

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


=head1 LICENSE AND COPYRIGHT

Copyright 2012 David Oswald.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut