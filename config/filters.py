SYSCALLS_DEFAULT_FILTERS = [
	"proc.exeline!='uname -p'",
	"proc.exeline!='uname -rs'",
	# "not (proc.exeline contains '/usr/local/bin/python -c import sys, setuptools, tokenize; sys.argv[0]')",
	# "not (proc.exeline contains '/usr/local/bin/python -u -c import sys, setuptools, tokenize; sys.argv[0]')",
	# "not (fd.name contains '/usr/local/lib/python3.8/')",
	# "not (fd.name contains '/lib/' and evt.arg.flags contains O_RDONLY)"
]


NETWORK_DEFAULT_FILTERS = [
    "pypi.org", 
    "files.pythonhosted.org",
]