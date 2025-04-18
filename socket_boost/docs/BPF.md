



# BPF logic

## Data structures






## Logic

### New Socket intercepted

1. Check if the dport or sport is in the map of ports to be intercepted
    - If not, return
2. Add the socket to the map of sockets to be intercepted
3. Pop a free_sk from the free_sk map
4. Add the association between the new_socket and the free_sk to the intercepted_sk map
    - It will be added two entries:
        - new_socket -> free_sk
        - free_sk -> new_socket


### New socket msg
1. read the dport and check if is a msg that need to be redirect to the proxy or to the app
2. depending on the direction, retrieve the association in the association map
3. redirect the sk to the associate path


### Socket destroy
1. check if the sk has any association
    - If not, return
2. Remove (both) the association from the association map
3. Push back the free_sk to the free_sk map
