##############################################################################
# Apache::AuthenIMAPClient - Copyright (c) 2002, John "Rowan" Littell
#
# This module is free software.  You may distribute and/or modify it under
# the same terms as Perl itself (either the GNU General Public Licence or
# the Artistic License, as specified in the Perl README file).
#
# THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
# WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
# $Id: AuthenIMAPClient.pm,v 1.2 2002/05/01 12:51:43 rowan Exp $
##############################################################################

package Apache::AuthenIMAPClient;

use strict;
use Apache::Constants qw/:common/;
use vars qw/%ENV/;
use Mail::IMAPClient;

$Apache::AuthenIMAPClient::VERSION = '0.02';
my $self="Apache::AuthenIMAPClient";

# Authentication checks agains IMAP server
sub handler {

    # get request object
    my $r = shift;

    # service only the first internal request
    return OK unless $r->is_initial_req;

    # check IP access list, if present
    my @iplist = split /\s+/, $r->dir_config('IMAPAllowed_IP');
    my $remote_ip = $r->connection->remote_ip;
    if (@iplist) {
	$r->log_reason($self . ': IP-based access not implemented yet', $r->uri);
    }

    # get IMAP server from config
    my $IMAPServer = $r->dir_config('IMAPServer');
    if ($IMAPServer eq "") {
        $r->log_reason($self . ': IMAPServer not specified', $r->uri);
        return AUTH_REQUIRED;
    }

    # get the port number, if specified
    my $IMAPPort = $r->dir_config('IMAPPort');
    $IMAPPort = 143 unless ($IMAPPort ne "");

    # get password user entered in browser
    my($res, $sent_pwd) = $r->get_basic_auth_pw;
    my $imap_password="";
    $imap_password=$sent_pwd;

    # decline if not basic
    return $res if $res;

    # get user name
    my $imap_username = $r->connection->user;

    # blank user name would cause problems
    unless($imap_username){
	$r->note_basic_auth_failure;
	$r->log_reason($self . ': no username supplied', $r->uri);
	return AUTH_REQUIRED;
    }
    unless($imap_password){
	$r->note_basic_auth_failure;
	$r->log_reason($self . ': no password supplied', $r->uri);
	return AUTH_REQUIRED;
    }

    # load apache config vars
    my $dir_config = $r->dir_config;   

    # contact IMAP server
    my $imap = Mail::IMAPClient->new (
		Server => $IMAPServer,
		Port => $IMAPPort,
		User => $imap_username,
		Password => $imap_password
    );
    if ($imap == undef) {
	my $err = $@;
	$r->note_basic_auth_failure;
	$r->log_reason ($self . ': IMAP error: $err', $r->uri);
	return AUTH_REQUIRED;
    } elsif ($imap->Connected() && $imap->Authenticated()) {
	# stash group id lookup for authorization check
	my ($gid) = (getpwnam($imap_username))[3];
	if (defined $gid) {
	    my ($group) = (getgrgid($gid))[0];
	    $r->notes($imap_username . 'Group', $group);
	}
	$r->push_handlers(PerlAuthzHandler => \&authz);
	$imap->logout();
	return OK;
    }

    return AUTH_REQUIRED;
}

# Authorization checks against the require list
sub authz {
 
    # get request object
    my $r = shift;
    my $requires = $r->requires;
    return OK unless $requires;

    # get user name
    my $name = $r->connection->user;

    for my $req (@$requires) {
	my ($require, @rest) = split /\s+/, $req->{requirement};

	# ok if user is simply authenticated
	($require eq 'valid-user') && (return OK);

	# ok if user is one of these users
	if ($require eq 'user') {
	    return OK if grep $name eq $_, @rest;
	}

	# ok if user is member of a required group.
	elsif ($require eq 'group') {
	    for my $grname (@rest) {
		return OK if ($r->notes($name . 'Group') == $grname);
		my @members = split /\s+/, (getgrnam($grname))[3];
		for my $m (@members) {
		    ($name eq $m) && (return OK);
		}
	    }
	}
    }

    $r->note_basic_auth_failure;
    $r->log_reason(
		   $self . ': user ' . $name . 
		   ' not member of required group', $r->uri
		   );
    return AUTH_REQUIRED;
    
}

1 ;

__END__

=pod

=head1 NAME

Apache::AuthenIMAPClient - Perform Basic User Authentication against
an IMAP server

=head1 SYNOPSIS

Allows users to give their username and e-mail password for
authentication against a IMAP server for access to restricted web
pages.

   #httpd.conf
   <Location />
      AuthName 'your-authentication-domain'
      AuthType Basic
      PerlSetVar IMAPServer imapserver.yoyodyne.com
      PerlAuthenHandler Apache::AuthenIMAPClient
      require group staff
      require user john lisa
      require valid-user
   </Location>

=head1 DESCRIPTION

This module performs basic user authentication by attempting to log in
to the IMAP server specified.  If a group requirement is specified,
the module attempts to authorize the user using local group
information (F</etc/group> and NIS have both been tested).

This module requires the Mail::IMAPClient module.  For lighter server
loads and increased speed, it is suggested that this module be used in
conjunction with the Apache::AuthenCache module.

=head1 CONFIGURATION

=head2 AuthType

Set the type of authentication.  Only B<Basic> is supported.

=head2 AuthName

Set the realm for basic authentication.

=head2 require

The require directive takes any of three forms:

  require valid-user
  require user user1 user2 ...
  require group group1 group2 ...

The first successfully authenticates and authorizes any successful
IMAP login.  The second only authorizes successful authentications for
the specified users.  The third does a local group membership check
for successful authentications and only authorizes users whose primary
or secondary groups are specified.

=head2 PerlSetVar IMAPServer imapserver.yoyodyne.com

This specifies the IMAP server to contact in order to perform the
authentication.

=head2 PerlSetVar IMAPPort 143

This specifies the TCP port to connect to on the IMAP server.  If left
unspecified, the default IMAP port, 143, is used.

=head1 AUTHOR

John "Rowan" Littell (littejo at earlham dot edu), scarfed the basic
skeleton of this module from the Apache::AuthenN2 module by Valerie
Delane.  Mario van den Heuvel (m.heuvel at sendrata dot com) supplied
a password existence check fix.

=head1 COPYRIGHT

Copyright (c) 2002, John "Rowan" Littell

This module is free software.  You may distribute and/or modify it under
the same terms as Perl itself (either the GNU General Public Licence or
the Artistic License, as specified in the Perl README file).

THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 SEE ALSO

mod_perl(3), Apache(3)

=cut
