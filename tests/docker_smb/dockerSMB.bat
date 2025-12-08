docker run -d --name samba-test   -p 139:139 -p 445:445   dperson/samba   -s "public;/share;yes;no;no;all"

