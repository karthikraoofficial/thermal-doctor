# Trust comes from the signing certificate

Downgrading a process to Info relies on the organisation in a valid Authenticode certificate, matched exactly against an allowlist. The file's company field is ignored because any binary can claim to be from Microsoft. Known findings likewise need a name plus a path or MSI product code, because a name alone would hide a lookalike. The cost is that a publisher who changes its certificate name returns to Medium until the allowlist is updated, which is the safer way to fail.
