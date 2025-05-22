xover
=====

LD_PRELOAD-based filename/dir overrider

Example:

    LD_PRELOAD=xover.so XOVER=/etc/ppp/chap-secrets=/root/encfs/chap-secrets pppd ...

Tricky example:

    LD_PRELOAD=xover.so XOVER='debug,noabs,qqq1=www1,../filename\,with\,comma=../filename\=with\=eqsign' program [args...]
