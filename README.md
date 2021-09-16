## The channel

Run
>`$ channel.py`

To connect a mac address (say 100), type `c 100` and press enter.
To see port numbers assigned, type `s` and press enter.
To disconnect a mac address (say 100), type `d 100` and press enter.
To quit, type `q` and press enter.

## The sender & Receiver

The flow contol scheme must be mentioned when starting as
>`$ sender.py <scheme>`
>and
>`$ receiver.py <scheme>`

where `<scheme>` can be:
1. `STWT` for Stop & Wait ARQ
2. `GOBN` for Go Back N
3. `SRARQ` for Selective Repeat ARQ

Then both scripts will prompt for `MAC` and `PORT`. Enter the mac address and the port number assigned to that mac by `channel.py`.

Then to estimate round trip time, on the sender side, enter `r <receiver's mac>`. Add the transmission times on both sides to estimate round trip time.

To send a file, enter `s <receiver's mac> <filename> <data bytes per packet>`.
`<data bytes per packet>` can range from `1` to `255`.

>Note:
>1. Taking the maximum window size of Go Back N to be k, Go Back N can get stuck if one of the two happen:
>		- last ACK is lost/corrupted
>		- any k consecutive ACKs are lost/corrupted
>2. The Selective Repeat ARQ has been modified so that if the sender sends a packet sequenced `s` and the receiver window starts at `s+1`, then a NAK is sent.