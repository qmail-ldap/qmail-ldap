#!/usr/bin/perl

# $localhost and $server need to changed
# If a file by the name "done" exists in the maildir we don't try to
# fetch the mails again.
# by Ingo Oppermann

use Mail::POP3Client;

# Variables

$path       = $ARGV[3];
$mailpath   = "./".$path;
$username   = $ARGV[0];
$pw         = $ARGV[1];
$server     = 'mail.pipeline.ch';
$localhost  = "mail.schweizerinserate.ch";
@filenames;

# Main

if(-e $mailpath."/done")
{
        ;
}
else
{
        $pop = new Mail::POP3Client($username,$pw,$server);
        $numofmails = $pop->Count;
        print $numofmails;
        for($i = 1; $i <= $numofmails; $i++)
        {
                $curtime = time();
                $random = rand();
                $filename = $curtime.".".$$.".".$random.$localhost;
                push(@filenames, $filename);
                open(OUT, ">".$mailpath."/tmp/".$filename);
                foreach($pop->Retrieve($i))
                {
                        print OUT $_, "\n";
                }
# Uncomment the next line if the retrieved mail should be deleted from
# the old pop server
        #       $pop->Delete($i);
                close(OUT);
        }
        $pop->Close;

        foreach(@filenames)
        {
                $filename = $_;
                $program = "mv $mailpath/tmp/$filename $mailpath/new/$filename";
                open(PROG, "|$program");
                close(PROG);
        }
        open(CHECK, ">$mailpath/done");
        print CHECK 1;
        close(CHECK);
}

exec "$ARGV[2] $ARGV[3]";

