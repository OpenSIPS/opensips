cat /tmp/opensips_reply &
cat > /tmp/opensips_fifo << EOF
:pdt_delete:opensips_reply
localhost
127.com

EOF
