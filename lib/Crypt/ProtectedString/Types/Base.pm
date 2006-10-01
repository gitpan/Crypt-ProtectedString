package Crypt::ProtectedString::Types::Base;

=head1 NAME

Crypt::ProtectedString::Types::Base - Base plugin for ProtectedStrings.

=head1 DESCRIPTION

This is the base storage plugin for ProtectedString.  It's intended as an example.  All licensing, author, and disclaimer are available in the L<Crypt::ProtectedString> documentation.

=cut

use strict;
use warnings;

use Digest::SHA1 qw(sha1_hex);
use MIME::Base64;
use Crypt::RSA;
use Crypt::RSA::Key::Public;
use Crypt::RSA::Key::Private;

our $keyids = ();

$keyids->{'#!1'} = ();

$keyids->{'#!1'}->{'public'} =  new Crypt::RSA::Key::Public ( Filename => $ENV{HOME} . "/secrets/rsa1.public" );
$keyids->{'#!1'}->{'private'} = new Crypt::RSA::Key::Private ( Filename => $ENV{HOME} . '/secrets/rsa1.private' ),

our $rsa = new Crypt::RSA ( ES => 'PKCS1v15', SS => 'PKCS1v15' );

sub new {
  my $class = shift;
  my $self;
  $self->{protected} = '';
  bless $self, $class;
  return $self;
}

sub can_display {
  # We can display everything, but poorly.
  return 1;
}

sub display {
  my $self = shift;
  my $type = shift;
  my $plaintext = shift;
  
  return sha1_hex($plaintext);
}

sub can_encrypt {
  return 1;
}

sub encrypt {
  my $self = shift;
  my $type = shift;
  my $plaintext = shift;
  my $keyid = shift;
  my $ciphertext = $rsa->encrypt( Message => $plaintext, Key => $keyids->{$keyid}->{"public"}, Armour => 0 ) || die ("Encryption error.");

  return MIME::Base64::encode_base64($ciphertext,'');
}

sub can_decrypt {
  return 1;
}

sub decrypt {
  my $self = shift;
  my $type = shift;
  my $ciphertext = shift;
  my $keyid = shift;
  my $plaintext = $rsa->decrypt( Cyphertext => MIME::Base64::decode_base64($ciphertext), Key => $keyids->{$keyid}->{"private"}, Armour => 0 ) || die ("Decryption error.");

  return $plaintext;
}

1;
