# Sanction
## An mitmproxy addon that tests authorisation controls

An mitmproxy addon that replicates the functionality of [Autorize](https://github.com/Quitten/Autorize). For more details check out the [Blog post](https://blog.aalsuwaidi.com/posts/sanction_mitmproxy/)

To use this addon clone the repository and call it with the **-s** flag.

`mitmproxy -s sanction.py --set names=preferredlocale --set values=en --set place=cookies`

![Replayed requests](https://blog.aalsuwaidi.com/images/filter2.png)