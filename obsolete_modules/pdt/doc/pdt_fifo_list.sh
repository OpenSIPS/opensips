cat /tmp/opensips_reply &
cat > /tmp/opensips_fifo << EOF
:pdt_list:opensips_reply
local
.
.

EOF
