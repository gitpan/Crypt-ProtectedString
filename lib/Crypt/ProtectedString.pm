package Crypt::ProtectedString;

use 5.008001;
use strict;
use warnings;

our $VERSION = '0.00_01';
$VERSION = eval $VERSION;  # see L<perlmodstyle>

# Format:
#   VERSION$TYPE$CIPHERTEXT$DISPLAYTEXT$reserved fields for future use
# 
# Version = #!PROTECTEDKEYID, where PROTECTEDKEYID is an integer reference
#   to the protected key to use...
# 
# For credit cards: TYPE=cc-number, optional field 1 = plaintext exp. date
#   For example: #!1$CC$base64-string-here$**** **** **** 1234$12/08$
# 
# For passwords: TYPE=password, DISPLAYTEXT= empty ($$).

use Module::Pluggable ( search_path => ['Crypt::ProtectedString::Types'],
			instantiate => 'new' );
use Carp;

our $delimiter = '$';
our $version_string = '#!1';

sub _choose_best {
  my $query = shift;
  my $prio_method = shift;
  my $exec_method = shift;

  my @priorities;

  foreach my $plugin ( plugins() ) {
    if ($plugin->can($prio_method) && $plugin->can($exec_method)) {
      my $priority = $plugin->$prio_method($query);
      push @priorities, [$plugin, $priority];
    }
  }

  @priorities = sort {$b->[1] <=> $a->[1]} @priorities;
  return $priorities[0]->[0];
}

sub new {
  my $class = shift;
  
  if ($#_ == -1) {
    return __PACKAGE__->_new_blank($class);
  } elsif ($#_ == 0) {
    my $protectedstr = shift;

    return __PACKAGE__->_new_from_protected($class, $protectedstr);
  } elsif ($#_ == 1) {
    my $datatype = shift;
    my $plaintext = shift;
    
    return __PACKAGE__->_new_from_plaintext($class, $datatype, $plaintext);
  } else {
    die("Invalid number of arguments in Secrets");
  }

}

sub _new_blank {
  my $class = shift;
  my $self;
  $self->{protected} = '';
  bless $self, $class;
}

sub _new_from_protected {
  my $class = shift;
  my $protectedstr = shift;
  my $self;
  $self->{protected} = $protectedstr;
  return bless $self, $class;
}

sub _new_from_plaintext {
  my $class = shift;
  my $type = shift;
  my $plaintext = shift;
  my $self;
  bless $self, $class;
  
  $self->{protected} = $self->protect($type,$plaintext);

  return $self;
}

sub display {
  my $self = shift;
  my @parr;
  my $protectedstr = $self->{protected};
  if ($#_ == -1) { 
    @parr = split(/$delimiter/, $self->{protected}, 5);
    return $parr[3];
  }
  elsif($#_ == 0) { 
    $protectedstr = $_[0];
    @parr = split(/$delimiter/, $protectedstr, 5);
    return $parr[3];
  }
  elsif($#_ == 1) { 
    my $type = $_[0];
    my $plaintext = $_[1]; 
    my $displayer = __PACKAGE__->_choose_best($type,'can_display','display');
    return $displayer->display($type, $plaintext);
  }
  else { die("Invalid arguments to ProtectedString create_display."); }
}

sub _protect {
  my $type = shift;
  my $plaintext = shift;
  my $displaytext = shift;
  my $ciphertext = __PACKAGE__->_encrypt($type, $plaintext, $version_string);

  return join ($delimiter, $version_string, $type, $ciphertext, $displaytext, @_);
}

sub protect {
  my $self = shift;
  my $type = shift;
  my $plaintext = shift;
  my $displaytext = $self->display($type, $plaintext);

  $self->{protected} = __PACKAGE__->_protect($type,$plaintext,$displaytext, @_);

  return $self->{protected};
}

sub _encrypt {
  my $type = shift;
  my $plaintext = shift;
  my $keyid = shift;
  $keyid ||= $version_string;
  my $cryptkeeper = __PACKAGE__->_choose_best($type,'can_encrypt','encrypt');

  return $cryptkeeper->encrypt($type,$plaintext,$keyid);
}

sub _decrypt {
  my $type = shift;
  my $ciphertext = shift;
  my $keyid = shift;

  my $cryptkeeper = __PACKAGE__->_choose_best($type,'can_decrypt','decrypt');

  return $cryptkeeper->decrypt($type, $ciphertext, $keyid);
}

sub decrypt {
  my $self = shift;
  my ($type,$ciphertext,$keyid);
  if ($#_ == -1) { 
    my @parr = split(/$delimiter/, $self->{protected}, 5);
    $type = $parr[1];
    $ciphertext = $parr[2];
    $keyid = $parr[0];
  } elsif($#_ == 0) {
    my @parr = split(/$delimiter/, $_[0], 5);
    $type = $parr[1];
    $ciphertext = $parr[2];
    $keyid = $parr[0];
  } elsif($#_ == 1) {
    $type = shift;
    $ciphertext = shift;
    $keyid = $version_string;
  } elsif($#_ == 2) {
    $type = shift;
    $ciphertext = shift;
    $keyid = shift;
    $keyid ||= $version_string;
  } else { die("Invalid arguments to ProtectedString decrypt."); }

  return __PACKAGE__->_decrypt($type,$ciphertext,$keyid);
}

sub AS_STRING {
  my $self = shift;

  return $self->{protected};

}

1;
__END__
=head1 NAME

Crypt::ProtectedString - protected format for storing sensitive data in databases, with partial display capability.

=head1 SYNOPSIS

I apologize for the lack of documentation at this stage.  The module is still in pre-alpha development.  Please bear with me.

=head1 DESCRIPTION

This module provides the ability to display, encrypt, decrypt, and parse sensitive data, such as credit card numbers.  It is intended for use with data that may need to be encrypted and partially displayed someplace (such as the last four digits of a credit card number on a user's account page on a web server), but must not be fully revealed (decrypted) anywhere except where absolutely necessary (such as the full credit card number to the credit card payment processing code).  This module is merely a framework for such a protected format.  The actual encryption and decryption (and security) must be implemented by the module user, in the form of plugins.


=head1 DISCLAIMER

THE AUTHOR MAKES NO PROMISE OF ANY KIND FOR THIS CODE.  It should not be used to store sensitive data in a production environment as it is not yet complete.

Or, to put it more explicitly, in legalese:

Author makes no warranties of any kind, expressed or implied, for this Perl module.  Author disclaims any warranty or merchantability of fitness for a particular purpose.  If you use this code and/or Perl module, you agree to indemnify, protect, defend, save and hold harmless Contractor against any damages suffered from operation or malfunction of your application, product, website, or any other object relying on this code, including loss of data, merchandise, valuables, financial records, cash, and any fees incurred by said operation or malfunction.  Author will not be held responsible for any damages users may suffer for any incidental, actual or real damages.

=head1 ACKNOWLEDGEMENTS

This module was inspired by Steve Friedl's ``A Proposal for Secure Storage of Credit Card Data'' (L<http://www.unixwiz.net/techtips/secure-cc.html>).  The plugin code used was inspired by (and is almost identical to) Jonathan Rockway's Angerwhale (L<http://www.jrock.us/trac/blog_software>) formatting system.

=head1 SEE ALSO

The ``Base'' example plugin for encryption/decryption using L<Crypt::RSA> is worth looking at, but you should make your own plugin to handle the various types of strings (credit card numbers, passwords, whatever...) and place them in the plugin search path, or subclass this and add to the search path.

You may contact me via e-mail, though I can not promise I will respond quickly.

=head1 AUTHOR

Ido Rosen, E<lt>ido AT cpan DOT orgE<gt>

If you wish to submit patches / help develop this module further, you are welcome to do so by contacting the author.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Ido Rosen

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, or under the BSD license.

=cut
