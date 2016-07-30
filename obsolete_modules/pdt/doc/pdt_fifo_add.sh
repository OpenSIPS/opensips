cat /tmp/opensips_reply &
cat > /tmp/opensips_fifo << EOF
:pdt_add:opensips_reply
localhost
*57
127.com

EOF
