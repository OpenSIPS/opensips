set pagination off
set print elements 0
set max-value-size unlimited

# usage: shm_hist_search 0x7faf32f44900
#  ... to search for SHM activity near an address of crash (latest -> oldest)
define shm_hist_search

  set $off = (long)&((struct struct_hist *)0).list
  set $first_obj = (struct struct_hist *)((char *)shm_hist->objects->prev - $off)
  set $last_obj = (struct struct_hist *)((char *)shm_hist->objects->next - $off)
  set $seconds = ($last_obj->created - $first_obj->created) / 1000000

  set $it = shm_hist->objects->next
  set $cnt = 0
  set $tot = 0
  set $hlen = shm_hist->len

  printf "OpenSIPS run time: %d hours, %d mins\n", *jiffies / 3600, (*jiffies % 3600) / 60
  printf "SHM history objects: %d now, %d all time\n", shm_hist->len, shm_hist->total_obj
  printf "Oldest SHM history object: %d seconds ago\n", $seconds

  printf "Digging in history for SHM activity close to address: %p ...\n", ($arg0)

  while ($tot < $hlen && $cnt < 100)
    set $tot = $tot + 1

    set $hist = (struct struct_hist *)((char *)$it - $off)
    set $p = $hist->obj

    if $p >= ($arg0) - 1000 && $p <= ($arg0)
      p $hist->obj
      p *$hist->actions
      set $cnt = $cnt + 1
    end

    if $tot % 100 == 0
      printf "%d objects analyzed so far ...\n", $tot
    end

    set $it = $it->next
  end
end

# usage: tcpcon_hist_search 0x7faf32f44900
#  ... to search for the history of a given connection (latest -> oldest)
define tcpcon_hist_search

  set $off = (long)&((struct struct_hist *)0).list
  set $first_obj = (struct struct_hist *)((char *)con_hist->objects->prev - $off)
  set $last_obj = (struct struct_hist *)((char *)con_hist->objects->next - $off)
  set $seconds = ($last_obj->created - $first_obj->created) / 1000000

  set $it = con_hist->objects->next
  set $tot = 0
  set $found = 0

  printf "OpenSIPS run time: %d hours, %d mins\n", *jiffies / 3600, (*jiffies % 3600) / 60
  printf "CON history objects: %d now, %d all time\n", con_hist->len, con_hist->total_obj
  printf "Oldest CON history object: %d seconds ago\n", $seconds

  printf "Digging in CON histories for connection: %p ...\n", ($arg0)

  while ((long)$it != (long)con_hist->objects && !$found)
    set $tot = $tot + 1

    set $hist = (struct struct_hist *)((char *)$it - $off)
    set $con = (struct tcp_connection *)$hist->obj

    if $con == ($arg0)
      set $found = 1

      printf "Found history for conn: %p\n", $con
      printf "Total actions: %d, max: %d (all shown below)\n", $hist->len, $hist->max_len
      printf "-------------------------------------------------\n"
      set $i = 0
      while ($i < $hist->max_len)
        p $hist->actions[$i++]
      end

      return
    else
      if $tot % 100 == 0
        printf "%d objects analyzed so far ...\n", $tot
      end
    end

    set $it = $it->next
  end

  if !$found
    printf "ERROR: Failed to locate history for conn %p !\n", ($arg0)
  end
end
