# $Id: Makefile.PL,v 1.2 2002/05/01 12:52:37 rowan Exp $

use ExtUtils::MakeMaker;

sub MY::libscan {
	my($self,$path) = @_;
	return '' if $path =~ /RCS/;
	$path;
}

WriteMakefile(
	'NAME'		=> 'Apache::AuthenIMAPClient',
	'VERSION_FROM'	=> 'AuthenIMAPClient.pm', 
	'AUTHOR'	=> 'John "Rowan" Littell <littejo@earlham.edu>',
	'ABSTRACT'	=> 'Perform Basic User Authentication against an IMAP server',
	'PREREQ_PM'	=> { Mail::IMAPClient => '2.1.4' },
	'dist'		=> { COMPRESS => 'gzip', SUFFIX => 'gz', },
);
