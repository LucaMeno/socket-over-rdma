


# RDMA lib

### rdma_context

```c
struct rdma_context
{
    struct rdma_event_channel *ec; // Event channel
    struct rdma_cm_id *listener;   // Listener ID (SERVER only)
    struct rdma_cm_id *conn;       // Connection ID
    struct ibv_pd *pd;             // Protection Domain
    struct ibv_mr *mr;             // Memory Region
    struct ibv_cq *cq;             // Completion Queue
    struct ibv_qp *qp;             // Queue Pair
    char *buffer;                  // Buffer to send
    size_t buffer_size;            // Size of the buffer
    struct rdma_cm_event *event;   // Event for connection management
    int cq_notify;                 // CQ notifications mode: 0 = polling, 1 = event-based
};
```

## Server

## rdma_setup_server()

setup server for RDMA communication:
- create an event channel to receive rdma events
    - connection request
    - connection established notification
- bind to an address
- create a listner and retuen the port/address

*params*:
- `sctx`: context to use
- `port`: port number to listen on
- `ib_dev`: ib device to use

*returns:*
- return 0 on success
- return -1 on failure


### rdma_wait_for_client()

wait for a client connection request:

- wait for a connection request
- create a PD, CQ, and QP
- accept the connection request
- wait for the connection to be established
- register the MR
- prepare the buffer to in case of send/receive

*params*:
- `sctx`: context to use

*returns:*
- return 0 on success
- return -1 on failure


## Client

### rdma_setup_client()

setup client for RDMA communication:
- create event channel to receive rdma events
    - address resolved
    - route resolved
    - connection established notification
- create connection identifier
- resolve the peer address which binds te connection identifier to a local RDMA device
- resolve the route to the peer address
- create PD, CQ, and QP
- register the MR


### rdma_connect_server()

connect to server:
- connetct to the server
- wait for the connection to be established

*params*:
- `sctx`: context to use

*returns:*
- return 0 on success
- return -1 on failure


## Common

### rdma_close() 

close the RDMA connection:
- destroy the QP
- destroy the CQ
- destroy the PD
- destroy the connection identifier
- destroy the event channel
- free the buffer

*params*:
- `sctx`: context to use

*returns:*
- return 0 on success
- return -1 on failure


### rdma_send()

send data to the other peer:
- post a send on SQ of the QP
- post completion to the local CQ

### rdma_recv()

receive data from the other peer:
- post a receive on the RQ of the QP
- on msg receive, the NIC writes the data into the buffer
- post completion to the local CQ

```
Sender:
[QP:SQ] --send--> ✈ --> Receiver
                                [QP: RQ]
                                ↓
                            [Buffer remoto scritto]
                                ↓
                            [Evento in CQ REMOTA]

Sender:
↓
[Evento in CQ LOCALE]

```

### rdma_write()

write data to the server:

- post a write on the SQ of the QP
- the NIC writes the data into the remote buffer
- post completion to the local CQ


### rdma_read()

read data from the server:
- post a read on the SQ of the QP
- the NIC reads the data from the remote buffer
- post completion to the local CQ


```
Client:
[QP: SQ] --write/read--> ✈ --> Server
                                  [No RQ, no CQ coinvolta]
                                  [Memoria remota letta/scritta]

Client:
↓
[Evento in CQ LOCALE]
```



| Caratteristica             | `Send/Receive`                        | `Read/Write`                          |
|---------------------------|----------------------------------------|----------------------------------------|
| **Serve la Receive Queue?** | ✅ Sì, obbligatoria                   | ❌ No                                   |
| **Serve postare buffer remoti?** | ✅ Sì                           | ❌ No (solo memoria registrata)         |
| **Evento in CQ remota?**   | ✅ Sì (quando ricevi un send)         | ❌ Mai                                   |
| **Evento in CQ locale?**   | ✅ Sì (quando invii o ricevi)         | ✅ Sì (quando read/write è finita)      |
| **CPU remota coinvolta?**  | ✅ Sì                                  | ❌ No                                   |


### rdma_notify_write()

notify the other peer that a write operation has been completed


### rdma_notify_read()

notify the other peer that a read operation has been completed