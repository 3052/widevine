# extractsecrets

## amazon

~~~
> play -i com.amazon.avod.thirdpartyclient -abi armeabi-v7a
~~~

works:

~~~
lib\armeabi-v7a\libAIVPlayReadyLicensing.so
�r5�&wv���|(ʖDG�gF37B��ʾ���l�]�R�7yޙ������?��%o�.@@�J      �����S/Eι�d�U���f���\�`&BR�~ױ�@8���+?�^lǰ�=g�y�3
. h|.f}'w�@ޠW�`�Lm嗲�{�        y������q7     ��<��O����R�o�'K`��xQ~h��� ����r�_�|��8ee����:U��+��~�(8j���S3�;}��>��B&�)�V�����6�0��N�U�"��X7CHAI\CERT�,X�LA������4���/��Ч?eۦ�oF�4�EjTO��,�G�:O�y�������`5,��������_��^�_��(��3�
~~~

## amc

fail:

~~~
> play -i com.amcplus.amcfullepisodes
~~~

fail:

~~~
> play -i com.amcplus.amcandroidtv -leanback
~~~

## cinemember

fail:

https://apkpure.com/cinemember/nl.peoplesplayground.audienceplayer.cinemember

## criterionchannel

fail:

~~~
> play -i com.criterionchannel
~~~

no TV version

## ctv

fail:

https://apkmirror.com/apk/bell-media-inc/ctv

fail:

https://apkmirror.com/apk/bell-media-inc/ctv-android-tv

## draken

fail:

https://apkcombo.com/draken-film/com.draken.android

## hulu

fail:

~~~
> play -i com.hulu.plus
~~~

next:

~~~
> play -i com.hulu.livingroomplus -abi armeabi-v7a -leanback
~~~

pass:

~~~
com.hulu.livingroomplus-config.armeabi_v7a-3009846\lib\armeabi-v7a\libwkf_support.so
163933:CHAI<CERT�
�U� ��?��^P�����N7䱣�k˱�/����l�RG�{��S4Hulu LLCWiiUWiiU�@`��ϡ-��s(�*��f���{��r!�#���g�DO��L��G��8��6�J�t���J���C��Lؓ��Lh#��C�ͪ�
�� �C�[��W'�o��YQy��h`M�X��,��
~~~

## itv

fail:

https://apkmirror.com/apk/itv-plc/itv-hub

fail:

https://apkmirror.com/apk/itv-plc/itv-hub-your-tv-player-watch-live-on-demand-android-tv

## max

fail:

~~~
> play -i com.wbd.stream
~~~

fail:

~~~
> play -i com.wbd.stream -leanback
~~~

## mubi

fail:

~~~
> play -i com.mubi
~~~

no TV version

## nbc

fail:

~~~
>  play -i com.nbcuni.nbc
~~~

fail:

~~~
> play -i com.nbcuni.nbc.androidtv -leanback
~~~

## paramount

fail:

~~~
> play -i com.cbs.app
~~~

fail:

~~~
> play -i com.cbs.ott -leanback
~~~

## plex

fail:

~~~
> play -i com.plexapp.android
~~~

no TV app

## pluto

fail:

~~~
> play -i tv.pluto.android
~~~

fail:

~~~
> play -i tv.pluto.android -leanback
~~~

## rakuten

fail:

https://apkmirror.com/apk/rakuten-tv/rakuten-tv-movies-tv-series

fail:

https://apkmirror.com/apk/rakuten-tv/rakuten-tv-movies-tv-series-android-tv

## roku

fail:

~~~
> play -i com.roku.web.trc -leanback
~~~

no phone app

## rtbf

fail:

~~~
> play -i be.rtbf.auvio
~~~

no TV app

## skyshowtime

fail:

- https://apkmirror.com/apk/skyshowtime/skyshowtime
- https://apkmirror.com/apk/skyshowtime/skyshowtime-android-tv

## tubitv

fail:

~~~
> play -i com.tubitv -abi armeabi-v7a
~~~

no TV app
