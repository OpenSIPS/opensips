use OpenSIPS::Constants;

sub pseudo {
	my $m = shift;

	my $varstring = "User: \$rU - UA: \$ua";

	my $v = $m->pseudoVar($varstring);
	OpenSIPS::log(L_INFO, "pseudovar substitution demo; original: '$varstring' - substituted: '$v'\n");

	return 1;
}

