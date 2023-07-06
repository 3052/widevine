# HLS

- <https://developer.apple.com/documentation/http_live_streaming/http_live_streaming_hls_authoring_specification_for_apple_devices/hls_authoring_specification_for_apple_devices_appendixes>
- <https://wikipedia.org/wiki/HTTP_Live_Streaming>

## CBC

Why does this:

~~~
#EXT-X-KEY:METHOD=AES-128,URI="https://cbsios-vh.akamaihd.net/i/temp_hd_galle...
~~~

mean CBC?

> An encryption method of AES-128 signals that Media Segments are completely
> encrypted using the Advanced Encryption Standard (AES) [`AES_128`] with a
> 128-bit key, Cipher Block Chaining (CBC)

https://datatracker.ietf.org/doc/html/rfc8216#section-4.3.2.4

## EXT-X-KEY

If IV is missing, then use KEY for both.

## Padding

> Public-Key Cryptography Standards #7 (PKCS7) padding [RFC5652]

- <https://wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7>
- https://datatracker.ietf.org/doc/html/rfc5652
- https://datatracker.ietf.org/doc/html/rfc8216#section-4.3.2.4

## Extensions

item        | format
------------|------------------------
Apple audio | mov,mp4,m4a,3gp,3g2,mj2
Apple video | mov,mp4,m4a,3gp,3g2,mj2
CBC audio   | mpegts
CBC video   | mpegts
NBC         | mpegts
Paramount   | mpegts
Roku        | mpegts
