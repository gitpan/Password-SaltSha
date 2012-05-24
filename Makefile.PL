use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Password::SaltSha',
    AUTHOR              => q{David Oswald <davido@cpan.org>},
    VERSION_FROM        => 'lib/Password/SaltSha.pm',
    ABSTRACT_FROM       => 'lib/Password/SaltSha.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' 		        => 0,
        'Math::Random::MT::Auto'	=> 0,
        'Crypt::SaltedHash' 		=> 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Password-SaltSha-*' },
);
