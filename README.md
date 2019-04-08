# Caching Proxy 

CProxy (CP) is a HTTP caching proxy server written in Python 3. With the aim of being able to surf the Internet completely offline, it will intercept Browser's HTTPs requests and decrypt the the traffic on-the-fly to store each successful HTTP response. 

This work is inspired by [coursera-dl](https://github.com/coursera-dl/coursera-dl) and [edx-dl](https://github.com/coursera-dl/edx-dl).

## Installation

```bash
pip3 install cproxy
```

If you want to install CP manually, you should install the following packages

- pyOpenSSL
- brotli
- chardet

Or simple run `pip install -r requirements.txt` in the package's home directory.

## Usage

1. Run the program by executing 

   ```bash
   $ cproxy
   ```

2. Change browser's proxy setting to

   ```bash
   http://loaclhost:8080
   ```

3. Visit "http://cp.ca" to install Certificate Authority (CA) (this is required. Otherwise you can only visit http websites off-line). For more detailed guidance, please refer to [mitmproxy - Certificates](https://docs.mitmproxy.org/stable/concepts-certificates/).

4. Viola, you can browse your favorite websites now.  

5. When disconnected from the Internet later, you can still visit those websites off-line. Or you can explicitly tell CP to use off-line mode

   ```bash
   cproxy -off
   ```

6. For more options, run `cproxy -h`

   ```bash
   $ cproxy -h                                                              
   usage: CachingProxy arguments [-h] [-cd CACHE_DIR] [-p PORT] [-off] [-d]
   
   optional arguments:
     -h, --help            show this help message and exit
     -cd CACHE_DIR, --cache_dir CACHE_DIR
                           where to store caches
     -p PORT, --port PORT  server listening port
     -off, --offline       Offline mode
     -d, --debug           Enable debugging mode
   ```

   

## TODOs

- [x] Caching HTTP/HTTPS websites
- [x] IPv6 support
- [ ] Pre-fetching
- [ ] Proxy (use proxychains for now)
- [ ] Youtube support  (lots of edx's videos are hosted on youtube. For now, youtube will be blocked when you visit course.edx.org thus to force player to use other video sources) 

## Thanks

The proxy server module of this project is based on [BaseProxy](https://github.com/qiyeboy/BaseProxy).
