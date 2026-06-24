// SHA1算法实现
function d6128651c8aff072e052f5522c01feaf9(input) {
	function rotate_left(n, s) {
		return (n << s) | (n >>> (32 - s));
	}

	function cvt_hex(val) {
		var str = "";
		var i;
		var v;

		for (i = 7; i >= 0; i--) {
			v = (val >>> (i * 4)) & 0x0f;
			str += v.toString(16);
		}
		return str;
	}

	var blockstart;
	var i, j;
	var W = new Array(80);
	var H0 = 0x67452301;
	var H1 = 0xEFCDAB89;
	var H2 = 0x98BADCFE;
	var H3 = 0x10325476;
	var H4 = 0xC3D2E1F0;
	var A, B, C, D, E;
	var temp;

	// 将输入字符串转换为UTF-8编码的字节数组
	var utf8Encode = new TextEncoder();
	var msg = utf8Encode.encode(input);

	var msg_len = msg.length;

	// 计算填充后的总长度
	var total_len = msg_len + 9;
	while (total_len % 64 !== 0) total_len++;

	// 创建填充后的消息数组
	var padded_msg = new Uint8Array(total_len);
	for (i = 0; i < msg_len; i++) {
		padded_msg[i] = msg[i];
	}
	padded_msg[msg_len] = 0x80; // 添加1位

	// 添加0位
	for (i = msg_len + 1; i < total_len - 8; i++) {
		padded_msg[i] = 0x00;
	}

	// 添加原始消息长度的64位表示
	var bit_len = msg_len * 8;
	for (i = total_len - 1; i >= total_len - 8; i--) {
		padded_msg[i] = bit_len & 0xff;
		bit_len >>>= 8;
	}

	// 处理每个512位块
	for (blockstart = 0; blockstart < total_len; blockstart += 64) {
		for (i = 0; i < 16; i++) {
			W[i] = padded_msg[blockstart + i * 4] << 24 |
				padded_msg[blockstart + i * 4 + 1] << 16 |
				padded_msg[blockstart + i * 4 + 2] << 8 |
				padded_msg[blockstart + i * 4 + 3];
		}

		for (i = 16; i < 80; i++) {
			W[i] = rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
		}

		A = H0;
		B = H1;
		C = H2;
		D = H3;
		E = H4;

		for (i = 0; i < 80; i++) {
			var f, k;

			if (i < 20) {
				f = (B & C) | ((~B) & D);
				k = 0x5A827999;
			} else if (i < 40) {
				f = B ^ C ^ D;
				k = 0x6ED9EBA1;
			} else if (i < 60) {
				f = (B & C) | (B & D) | (C & D);
				k = 0x8F1BBCDC;
			} else {
				f = B ^ C ^ D;
				k = 0xCA62C1D6;
			}

			temp = (rotate_left(A, 5) + f + E + k + W[i]) & 0xffffffff;
			E = D;
			D = C;
			C = rotate_left(B, 30);
			B = A;
			A = temp;
		}

		H0 = (H0 + A) & 0xffffffff;
		H1 = (H1 + B) & 0xffffffff;
		H2 = (H2 + C) & 0xffffffff;
		H3 = (H3 + D) & 0xffffffff;
		H4 = (H4 + E) & 0xffffffff;
	}

	return cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);
}

// SHA256算法实现
function be75204f81ea1407007cd733754c02666(input) {
	var K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];

	function rightRotate(value, amount) {
		return (value >>> amount) | (value << (32 - amount));
	}

	// 将输入字符串转换为UTF-8编码的字节数组
	var utf8Encode = new TextEncoder();
	var msg = utf8Encode.encode(input);

	var msg_len = msg.length;
	var total_len = msg_len + 9;
	while (total_len % 64 !== 0) total_len++;

	// 创建填充后的消息数组
	var padded_msg = new Uint8Array(total_len);
	for (var i = 0; i < msg_len; i++) {
		padded_msg[i] = msg[i];
	}
	padded_msg[msg_len] = 0x80; // 添加1位

	// 添加0位
	for (i = msg_len + 1; i < total_len - 8; i++) {
		padded_msg[i] = 0x00;
	}

	// 添加原始消息长度的64位表示
	var bit_len = msg_len * 8;
	for (i = total_len - 1; i >= total_len - 8; i--) {
		padded_msg[i] = bit_len & 0xff;
		bit_len >>>= 8;
	}

	// 初始化哈希值
	var h0 = 0x6a09e667;
	var h1 = 0xbb67ae85;
	var h2 = 0x3c6ef372;
	var h3 = 0xa54ff53a;
	var h4 = 0x510e527f;
	var h5 = 0x9b05688c;
	var h6 = 0x1f83d9ab;
	var h7 = 0x5be0cd19;

	// 处理每个512位块
	for (var blockstart = 0; blockstart < total_len; blockstart += 64) {
		var w = new Array(64);

		// 将块分解为16个32位字
		for (i = 0; i < 16; i++) {
			w[i] = padded_msg[blockstart + i * 4] << 24 |
				padded_msg[blockstart + i * 4 + 1] << 16 |
				padded_msg[blockstart + i * 4 + 2] << 8 |
				padded_msg[blockstart + i * 4 + 3];
		}

		// 扩展16个字为64个字
		for (i = 16; i < 64; i++) {
			var s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
			var s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
			w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
		}

		// 初始化工作变量
		var a = h0;
		var b = h1;
		var c = h2;
		var d = h3;
		var e = h4;
		var f = h5;
		var g = h6;
		var h = h7;

		// 主循环
		for (i = 0; i < 64; i++) {
			var S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
			var ch = (e & f) ^ ((~e) & g);
			var temp1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffff;
			var S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
			var maj = (a & b) ^ (a & c) ^ (b & c);
			var temp2 = (S0 + maj) & 0xffffffff;

			h = g;
			g = f;
			f = e;
			e = (d + temp1) & 0xffffffff;
			d = c;
			c = b;
			b = a;
			a = (temp1 + temp2) & 0xffffffff;
		}

		// 添加压缩后的块到当前哈希值
		h0 = (h0 + a) & 0xffffffff;
		h1 = (h1 + b) & 0xffffffff;
		h2 = (h2 + c) & 0xffffffff;
		h3 = (h3 + d) & 0xffffffff;
		h4 = (h4 + e) & 0xffffffff;
		h5 = (h5 + f) & 0xffffffff;
		h6 = (h6 + g) & 0xffffffff;
		h7 = (h7 + h) & 0xffffffff;
	}

	// 生成最终的哈希值
	function toHex(val) {
		var str = "";
		for (var i = 7; i >= 0; i--) {
			var v = (val >>> (i * 4)) & 0x0f;
			str += v.toString(16);
		}
		return str;
	}

	return toHex(h0) + toHex(h1) + toHex(h2) + toHex(h3) + toHex(h4) + toHex(h5) + toHex(h6) + toHex(h7);
}

function i97aa42a8195579c18e8c517676953098(message) {
    message = unescape(encodeURIComponent(message));

    function rotateLeft(lValue, iShiftBits) {
        return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }

    function addUnsigned(lX, lY) {
        var lX4, lY4, lX8, lY8, lResult;
        lX8 = (lX & 0x80000000);
        lY8 = (lY & 0x80000000);
        lX4 = (lX & 0x40000000);
        lY4 = (lY & 0x40000000);
        lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
        if (lX4 & lY4) {
            return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        }
        if (lX4 | lY4) {
            if (lResult & 0x40000000) {
                return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            } else {
                return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
            }
        } else {
            return (lResult ^ lX8 ^ lY8);
        }
    }

    function F(x, y, z) {
        return (x & y) | ((~x) & z);
    }

    function G(x, y, z) {
        return (x & z) | (y & (~z));
    }

    function H(x, y, z) {
        return (x ^ y ^ z);
    }

    function I(x, y, z) {
        return (y ^ (x | (~z)));
    }

    function FF(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }

    function GG(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }

    function HH(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }

    function II(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }

    function convertToWordArray(message) {
        var lWordCount, lMessageLength = message.length,
            lNumberOfWords_temp1 = lMessageLength + 8,
            lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64,
            lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16,
            lWordArray = new Array(lNumberOfWords);
        for (lWordCount = 0; lWordCount < lNumberOfWords; lWordCount++) {
            lWordArray[lWordCount] = 0;
        }
        for (lWordCount = 0; lWordCount < lMessageLength; lWordCount++) {
            lWordArray[lWordCount >> 2] |= message.charCodeAt(lWordCount) << ((lWordCount % 4) * 8);
        }
        lWordArray[lWordCount >> 2] |= 0x80 << ((lWordCount % 4) * 8);
        lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
        lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
        return lWordArray;
    }

    function wordToHex(lValue) {
        var wordToHexValue = '',
            wordToHexValue_temp = '',
            lByte, lCount;
        for (lCount = 0; lCount <= 3; lCount++) {
            lByte = (lValue >>> (lCount * 8)) & 255;
            wordToHexValue_temp = '0' + lByte.toString(16);
            wordToHexValue += wordToHexValue_temp.substr(wordToHexValue_temp.length - 2, 2);
        }
        return wordToHexValue;
    }
    var x = [],
        k, AA, BB, CC, DD, a, b, c, d, S11 = 7,
        S12 = 12,
        S13 = 17,
        S14 = 22,
        S21 = 5,
        S22 = 9,
        S23 = 14,
        S24 = 20,
        S31 = 4,
        S32 = 11,
        S33 = 16,
        S34 = 23,
        S41 = 6,
        S42 = 10,
        S43 = 15,
        S44 = 21;
    x = convertToWordArray(message);
    a = 0x67452301;
    b = 0xEFCDAB89;
    c = 0x98BADCFE;
    d = 0x10325476;
    for (k = 0; k < x.length; k += 16) {
        AA = a;
        BB = b;
        CC = c;
        DD = d;
        a = FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
        d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
        c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
        b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
        a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
        d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
        c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
        b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
        a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
        d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
        c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
        b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
        a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
        d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
        c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
        b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
        a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
        d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
        c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
        b = GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
        a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
        d = GG(d, a, b, c, x[k + 10], S22, 0x2441453);
        c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
        b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
        a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
        d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
        c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
        b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
        a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
        d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
        c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
        b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
        a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
        d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
        c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
        b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
        a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
        d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
        c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
        b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
        a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
        d = HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
        c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
        b = HH(b, c, d, a, x[k + 6], S34, 0x4881D05);
        a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
        d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
        c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
        b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
        a = II(a, b, c, d, x[k + 0], S41, 0xF4292244);
        d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
        c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
        b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
        a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
        d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
        c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
        b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
        a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
        d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
        c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
        b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
        a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
        d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
        c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
        b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
        a = addUnsigned(a, AA);
        b = addUnsigned(b, BB);
        c = addUnsigned(c, CC);
        d = addUnsigned(d, DD);
    }
    var temp = wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d);
    return temp.toLowerCase();
}

function l6b857c6569ba9f3819520ac0aae15b7c(text, key) {
    text = utf8Encode(text);
    key = utf8Encode(key);

    let s = new Array(256);
    let j = 0;
    let x;

    for (let i = 0; i < 256; i++) {
        s[i] = i;
    }

    for (let i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
    }

    let i = 0;
    j = 0;
    let ciphertext = '';

    for (let n = 0; n < text.length; n++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
        ciphertext += String.fromCharCode(text.charCodeAt(n) ^ s[(s[i] + s[j]) % 256]);
    }

    return ciphertext;
}

function y8df6b7922f710809324973db5468ffe3(ciphertext, key) {
    ciphertext = ciphertext;
    key = utf8Encode(key);

    let s = new Array(256);
    let j = 0;
    let x;

    for (let i = 0; i < 256; i++) {
        s[i] = i;
    }

    for (let i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
    }

    let i = 0;
    j = 0;
    let plaintext = '';

    for (let n = 0; n < ciphertext.length; n++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
        plaintext += String.fromCharCode(ciphertext.charCodeAt(n) ^ s[(s[i] + s[j]) % 256]);
    }

    return utf8Decode(plaintext);
}

function utf8Encode(str) {
    return unescape(encodeURIComponent(str));
}

function utf8Decode(str) {
    return decodeURIComponent(escape(str));
}

function ia332da218853b6977297dfbc2c571979(hex) {
    let bytes = [];
    for (let i = 0; i < hex.length - 1; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return String.fromCharCode.apply(String, bytes);
}

function ff0b1ec8185c9033e3515419d31aa1fdf(bin) {
    let hex = '';
    for (let i = 0; i < bin.length; i++) {
        hex += ('0' + bin.charCodeAt(i)
            .toString(16))
            .slice(-2);
    }
    return hex;
}

const customBase64Key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function bd950565c426cc4459e62d93408bd89eb(input) {
    const utf8String = unescape(encodeURIComponent(input));
    const base64 = btoa(utf8String);
    return base64.replace(/[A-Za-z0-9+/]/g, char => customBase64Key[customBase64Key.indexOf(char)]);
}

function b6a7513f52a235baf23d45ac76ad09f64(input) {
    const base64 = input.replace(/[A-Za-z0-9+/]/g, char => customBase64Key[customBase64Key.indexOf(char)]);
    const utf8String = atob(base64);
    return decodeURIComponent(escape(utf8String));
}

function k4d6419d64b89195dd5ea7817c7e90384(input, base64Chars) {
  // Convert input string to UTF-8 bytes
  const utf8Bytes = new TextEncoder().encode(input);
  
  let output = "";
  let padding = "";
  let i = 0;
  const len = utf8Bytes.length;

  while (i < len) {
    let b1 = utf8Bytes[i];
    let b2 = utf8Bytes[i + 1];
    let b3 = utf8Bytes[i + 2];

    if (b2 === undefined) {
      b2 = 0;
      padding += "=";
    }
    if (b3 === undefined) {
      b3 = 0;
      padding += "=";
    }

    let combined = (b1 << 16) + (b2 << 8) + b3;
    output += base64Chars.charAt((combined >> 18) & 0x3F);
    output += base64Chars.charAt((combined >> 12) & 0x3F);
    output += base64Chars.charAt((combined >> 6) & 0x3F);
    output += base64Chars.charAt(combined & 0x3F);

    i += 3;
  }

  return output.substring(0, output.length - padding.length) + padding;
}

function we6ae339cf0a820b3d163c944236fb25c(input, base64Chars) {
  const base64DecodeChars = {};
  for (let i = 0; i < base64Chars.length; i++) {
    base64DecodeChars[base64Chars.charAt(i)] = i;
  }

  let padding = 0;
  if (input.endsWith("=")) padding++;
  if (input.endsWith("==")) padding++;

  let output = [];
  let i = 0;
  const len = input.length;

  while (i < len - padding) {
    let c1 = base64DecodeChars[input.charAt(i)];
    let c2 = base64DecodeChars[input.charAt(i + 1)];
    let c3 = base64DecodeChars[input.charAt(i + 2)];
    let c4 = base64DecodeChars[input.charAt(i + 3)];

    if (c3 === undefined) c3 = 0;
    if (c4 === undefined) c4 = 0;

    let combined = (c1 << 18) + (c2 << 12) + (c3 << 6) + c4;
    output.push((combined >> 16) & 0xFF);
    output.push((combined >> 8) & 0xFF);
    output.push(combined & 0xFF);

    i += 4;
  }

  // Trim padding
  if (padding === 1) {
    output = output.slice(0, -1);
  } else if (padding === 2) {
    output = output.slice(0, -2);
  }

  // Convert bytes back to string (UTF-8)
  return new TextDecoder().decode(new Uint8Array(output));
}

function geyKamiHc(){
    var kami = localStorage.getItem('weiyanKami');
    return kami == null ? "" : kami
}

function getDeviceId() {
    var deviceId = localStorage.getItem('deviceId');
    if (!deviceId) {
        deviceId = generateDeviceId();
        localStorage.setItem('deviceId', deviceId);
    }
    return deviceId;
}

function generateDeviceId() {
    var chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var deviceId = '';
    for (var i = 0; i < 16; i++) {
        deviceId += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return deviceId;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function wyDateTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

function HttpPost(url, data, callback) {
  var xhr = new XMLHttpRequest();
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
      if (xhr.status === 200) {
        callback(null, xhr.responseText);
      } else {
        callback(xhr.status, null);
      }
    }
  };
  xhr.send(data);
}

const q4e55c256ac42adbafa29c5d83d57463c = "https://wy.llua.cn/v2/"

// 系统公告
HttpPost(q4e55c256ac42adbafa29c5d83d57463c + "ab52af82d9eab7c655980dad83446b05",bd950565c426cc4459e62d93408bd89eb(ff0b1ec8185c9033e3515419d31aa1fdf(l6b857c6569ba9f3819520ac0aae15b7c(ff0b1ec8185c9033e3515419d31aa1fdf(l6b857c6569ba9f3819520ac0aae15b7c(bd950565c426cc4459e62d93408bd89eb(ff0b1ec8185c9033e3515419d31aa1fdf(ff0b1ec8185c9033e3515419d31aa1fdf(ff0b1ec8185c9033e3515419d31aa1fdf("id=RdgIYDtDtGX")))),"k238c4f2b4f309e88e5c023c49a1a21")),"vf796ed90c1b1b6a998a5"))),function(code,data){
    if (code) {
        confirm("请求失败，状态码：" + error);
    } else {
        const notice_data = JSON.parse(y8df6b7922f710809324973db5468ffe3(ia332da218853b6977297dfbc2c571979(data),"gab05ea78871dd909c7331400fdb50f7a"))
        if (notice_data.code == 70470) {
            confirm("公告：" + notice_data.msg.app_gg)
        } else {
            confirm("公告获取失败")
        }
        l4e56ef7777cf56bbd36bd2f856d86337()
    }
})

// 单码登录
function l4e56ef7777cf56bbd36bd2f856d86337(){
    const h3f867e7f654b06b34df5624f2a5ae675 = prompt("请输入卡密",geyKamiHc())
    const pd786bb33b7b2f38761b0e26deb6b28cb = getDeviceId()
    const d96f69035faf28c9097d44b442cecc49e = Math.floor(new Date().getTime() / 1000);
    const ufa99acc4258ad5d8f21cc5c60aa53de8 = getRandomInt(10000, 99999);
    const z9a668193fbd59a1cb24ecd028fd634c1 = i97aa42a8195579c18e8c517676953098("kami=" + h3f867e7f654b06b34df5624f2a5ae675 + "&markcode=" + pd786bb33b7b2f38761b0e26deb6b28cb + "&t=" + d96f69035faf28c9097d44b442cecc49e + "&sd1f7124c4f94f84b50daecfbf2aa961")
    HttpPost(q4e55c256ac42adbafa29c5d83d57463c + "ab52af82d9eab7c655980dad83446b05",bd950565c426cc4459e62d93408bd89eb(ff0b1ec8185c9033e3515419d31aa1fdf(l6b857c6569ba9f3819520ac0aae15b7c(ff0b1ec8185c9033e3515419d31aa1fdf(l6b857c6569ba9f3819520ac0aae15b7c(bd950565c426cc4459e62d93408bd89eb(ff0b1ec8185c9033e3515419d31aa1fdf(ff0b1ec8185c9033e3515419d31aa1fdf(ff0b1ec8185c9033e3515419d31aa1fdf("id=JLBIQjUQ8qJ&kami=" + h3f867e7f654b06b34df5624f2a5ae675 + "&markcode=" + pd786bb33b7b2f38761b0e26deb6b28cb + "&t=" + d96f69035faf28c9097d44b442cecc49e + "&sign=" + z9a668193fbd59a1cb24ecd028fd634c1 + "&value=" + ufa99acc4258ad5d8f21cc5c60aa53de8 +"")))),"k238c4f2b4f309e88e5c023c49a1a21")),"vf796ed90c1b1b6a998a5"))),function(code,o029b1fc1abe859d9c19160104fd60ae7){
        if (code) {
            confirm("请求失败，状态码：" + code);
        } else {
            const k642a37f3993ebbe6402300482e7ded74 = JSON.parse(y8df6b7922f710809324973db5468ffe3(ia332da218853b6977297dfbc2c571979(we6ae339cf0a820b3d163c944236fb25c(we6ae339cf0a820b3d163c944236fb25c(we6ae339cf0a820b3d163c944236fb25c(y8df6b7922f710809324973db5468ffe3(ia332da218853b6977297dfbc2c571979(o029b1fc1abe859d9c19160104fd60ae7),"xff6fd802b5d728a7ca42"),"/CsAO9Dhk0FpfqETL+68I7b5iZwVgc4oleSK1vujPXQNJxMHBGtrWznR3UYa2mdy"),"RvdoiLEje4ZuNTIaQVXKCrh8w5fScUpxPqykOFgH2109Y7BA3zlGs/W6+DJMntmb"),"RAlIvPcL9BeyuHKGJfaC8D6YOoXVthpb42NrMdgiE/Uz1xZm7k053qSsTWwjQ+Fn")),"hd3e1da5c50e62f326e8db81b55ef9b0bcb3b"))
            if (k642a37f3993ebbe6402300482e7ded74.oa5d4fb2339c3f4e23efb04bac0f82700==49118 && k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.w91151cc365d8c7ae4765b472941fd874=="ac1c664cfcd71ee932b9b73dc0cbb1e6"){
                if (k642a37f3993ebbe6402300482e7ded74.d1a4aadec01258f9cac5d6c03f77424e9-d96f69035faf28c9097d44b442cecc49e>30 || k642a37f3993ebbe6402300482e7ded74.d1a4aadec01258f9cac5d6c03f77424e9-d96f69035faf28c9097d44b442cecc49e<-30){
                    confirm("设备时间不准")
                }else{
                    if (k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.mcaf5860270aa341a53 != be75204f81ea1407007cd733754c02666(d6128651c8aff072e052f5522c01feaf9(be75204f81ea1407007cd733754c02666(""+"sd1f7124c4f94f84b50daecfbf2aa961"+""+z9a668193fbd59a1cb24ecd028fd634c1+""))) || k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.z90b2ef0b5dc349 != d6128651c8aff072e052f5522c01feaf9(be75204f81ea1407007cd733754c02666(d6128651c8aff072e052f5522c01feaf9(""+"sd1f7124c4f94f84b50daecfbf2aa961"+""+d96f69035faf28c9097d44b442cecc49e+""))) || k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.e6abfd1ad != d6128651c8aff072e052f5522c01feaf9(d6128651c8aff072e052f5522c01feaf9(i97aa42a8195579c18e8c517676953098(""+k642a37f3993ebbe6402300482e7ded74.oa5d4fb2339c3f4e23efb04bac0f82700+""+k642a37f3993ebbe6402300482e7ded74.d1a4aadec01258f9cac5d6c03f77424e9+""+ufa99acc4258ad5d8f21cc5c60aa53de8+""))) || k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.sfbffbbba != d6128651c8aff072e052f5522c01feaf9(i97aa42a8195579c18e8c517676953098(""+k642a37f3993ebbe6402300482e7ded74.d1a4aadec01258f9cac5d6c03f77424e9+""+"sd1f7124c4f94f84b50daecfbf2aa961"+"")) || k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.gfc160adba084005c != i97aa42a8195579c18e8c517676953098(be75204f81ea1407007cd733754c02666(""+k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.z6197dca2449149b275e869ca54c4ab69+""+k642a37f3993ebbe6402300482e7ded74.oa5d4fb2339c3f4e23efb04bac0f82700+""+k642a37f3993ebbe6402300482e7ded74.d1a4aadec01258f9cac5d6c03f77424e9+""))){
                        confirm("校验失败")
                    }else{
                        if (k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.s85911a896a817c859963ad87e483fe07 == "single"){
                            confirm("登录成功\n剩余登录次数:" + k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.z18de79486db175c390933ea3d7b6bc74)
                        }else{
                            confirm("登录成功\n到期时间:" + wyDateTime(k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515.f21b3fb1204ae571a094c3c41997fe6fb))
                        }
                        document.body.style.display = "block";
                        localStorage.setItem('weiyanKami', h3f867e7f654b06b34df5624f2a5ae675);
                        return
                    }
                }
            }else{
                confirm(k642a37f3993ebbe6402300482e7ded74.a4caed3e298ce7fb7ce2b308e20364515)
            }
        
        }
        l4e56ef7777cf56bbd36bd2f856d86337()
    })
}


