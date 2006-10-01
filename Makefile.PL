use 5.008001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Crypt::ProtectedString',
    VERSION_FROM      => 'lib/Crypt/ProtectedString.pm', # finds $VERSION
    PREREQ_PM         => { 'Carp' => 0, 'Crypt::RSA' => 0, 'Crypt::RSA::Key::Public' => 0, 'Crypt::RSA::Key::Private' => 0, 'Digest::SHA1' => 0, 'Module::Pluggable' => 0 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Crypt/ProtectedString.pm', # retrieve abstract from module
       AUTHOR         => 'ןזור ודיע (Ido Rosen) <ido@cpan.org>') : ()),
);
