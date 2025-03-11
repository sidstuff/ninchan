async function getHashArr(str) {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer));
}
async function getHash(str) {
  const hashArr = await getHashArr(str);
  return hashArr.map((b) => b.toString(16).padStart(2, "0")).join("");
}
function genPrivKey(sizeInBytes) {
  const array = new Uint8Array(sizeInBytes);
  self.crypto.getRandomValues(array);
  return Array.from(array).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToDec(hex) {
  if (hex.length % 2) { hex = '0' + hex; }
  return BigInt('0x' + hex).toString(10);
}
const shortDelay = 3000;
const ec = new elliptic.ec('secp256k1');
const subject = document.getElementById('subject');
const comment = document.getElementById('comment');
const signature = document.getElementById('signature');
const sign = document.getElementById('sign');
async function setSign() {
  if (sign.checked) {
    let key = localStorage.getItem('priv-key');
    if ( key == null ) {
      key = genPrivKey(32); // 32 bytes == 256 bits
      localStorage.setItem('priv-key', key);
    }
    key = ec.keyFromPrivate(key);
    const timestamp = Date.now();
    const hash = await getHashArr(JSON.stringify([timestamp, subject.value, comment.value]));
    const derSign = key.sign(hash).toDER();
    const recoveryId = ec.getKeyRecoveryParam(hash, derSign, key.getPublic());
    signature.value = JSON.stringify([derSign, recoveryId, timestamp]);
  } else { signature.value = ''; } // Clear the previous signature if any
}
const submitButton = document.getElementById('submit-button');
let clickedJustNow = false;
submitButton.onclick = async function() {
  if (clickedJustNow == false) {
    clickedJustNow = true;
    setTimeout(() => { clickedJustNow = false; }, shortDelay); // debouncing
    await setSign();
    document.getElementsByTagName('form')[0].submit();
    submitButton.innerHTML = 'Posted!';
    document.getElementById('reload-link').style.display = 'inline';
  }
}
const comments = document.getElementById('comments');
async function getImSize(url) { // image size in bytes, returns -1 if video
  try {
    const response = await fetch(url, {method: 'HEAD'});
    if (!response.ok) {
      throw new Error(`Response status: ${response.status}`);
    }
    if (response.headers.get('content-type').startsWith('video')) {
      return -1;
    }
    if (response.headers.get('content-type').startsWith('image')) {
      return Number(response.headers.get('content-length'));
    }
    return 0;
  } catch (error) {
    return 0;
  }
}
let maxVideos = 3;
let maxImages = 2;
let maxSize = 1000; // KB
let desc = true;
async function addComment(row) {
  const id = row[4].substring(9); // substring(9) removes the 'undefined' prefix
  const postTime = Date.parse(`${row[0]} GMT`);
  let tripTag = '';
  if (row[3]) {
    const [derSign, recoveryId, timestamp] = JSON.parse(row[3].substring(9));
    const hash = await getHash(JSON.stringify([timestamp, row[1], row[2]]));
    const tripcode = await getHash(JSON.stringify(ec.recoverPubKey(hexToDec(hash), derSign, recoveryId)));
    if ( Math.abs(postTime-timestamp) < shortDelay ) {
      tripTag = `<span class="tripcode" title="${tripcode}">${tripcode.substring(0,8)}</span>&#32;&#32;&#32;&#32;`;
    }
  }
  const commentDiv = document.createElement('div');
  commentDiv.style.overflow = 'hidden';
  commentDiv.setAttribute('id', `${id}`);
  commentDiv.innerHTML = `&#32;&#32;&#32;&#32;<em>${new Date(postTime).toLocaleString()}</em>&#32;&#32;&#32;&#32;<span class="id" onclick="reply(event.target)" title="Click to reply">No. ${id}</span>&#32;&#32;&#32;&#32;${tripTag}<button onclick="toggle(event.target)">▲</button>`;
  const subject = document.createElement('strong');
  subject.textContent = row[1];
  commentDiv.prepend(subject);
  const para = document.createElement('p');
  para.style.overflow = 'auto';
  function sanitize(match) {
    return match.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#x27');
  }
  function desanitize(match) {
    return match.replaceAll('&amp;', '&').replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&#x27', "'");
  }
  let imCount = 0, vidCount = 0;
  async function replacerFunction(match) {
    let url = desanitize(match), trail = '';
    while ( '.,;'.includes(url.slice(-1)) ) { trail = url.slice(-1) + trail; url = url.slice(0, -1); }
    let realurl = url;
    if ( !/^[-.a-z0-9]+:/.test(url) ) { realurl = 'http://' + url; }
    let tag = `<a href="${sanitize(realurl)}">${sanitize(url)}</a>${trail}`;
    if (imCount < maxImages || vidCount < maxVideos) {
      const imSize = await getImSize(url);
      if (imSize == -1 && vidCount < maxVideos) {
        tag = `<video src="${sanitize(realurl)}" controls preload="metadata"></video>${trail}`;
        vidCount++;
      } else if (imSize > 0 && imSize <= maxSize*1000 && imCount < maxImages) {
        tag = `<img src="${sanitize(realurl)}" loading="lazy">${trail}`;
        imCount++;
      }
    }
    return tag;
  }
  async function replaceAsync(str, regex, replacer) {
    let matches = [];
    while (match = regex.exec(str)) {
      matches.push([match[0], match.index, match[0].length])
    }
    let offset = 0;
    for (const m of matches) {
      const replaceWith = await replacer(m[0]);
      str = str.substring(0, m[1] + offset) + replaceWith + str.substring(m[1] + m[2] + offset, str.length);
      offset += replaceWith.length - m[2];
    }
    return str;
  }
  const replaced = await replaceAsync(sanitize(row[2]), /([a-z]{3,}:\/{0,3}([-.:\p{L}\p{N}]+@)?|([-.:\p{L}\p{N}]+@)?[-\p{L}\p{N}]+\.)([-\p{L}\p{N}]+\.)*[\p{L}\p{N}]{2,}(:[0-9]+)?([\/?#]\S*)?/gu, replacerFunction);
  para.innerHTML = replaced.replace(/&gt;&gt;[0-9]+/g, (match) => { return `<a href="javascript:void(0)" onclick="redirect(${match.substring(8)})">${match}</a>`; })
                           .replace(/^&gt;.*$/gm, (match) => { return `<span class="greentext">${match}</span>`; });
  commentDiv.append(para);
  if (desc) {
    comments.append(commentDiv);
    comments.append(document.createElement('hr'));
  } else {
    comments.prepend(document.createElement('hr'));
    comments.prepend(commentDiv);
  }
  return Number(id);
}
/*

Wondering what that monster regex was?
We need to handle URLs like example.com http://localhost:8000 mailto:someone@example.com ftp://username:password@example.com

/([a-z]{3,}:\/{0,3}([-.:\p{L}\p{N}]+@)?|([-.:\p{L}\p{N}]+@)?[-\p{L}\p{N}]+\.)([-\p{L}\p{N}]+\.)*[\p{L}\p{N}]{2,}(:[0-9]+)?([\/?#]\S*)?/gu

(                        a protocol scheme
   [a-z]{3,}               protocol name
   :                       colon
   \/{0,3} optional        slashes
   ([-.:\p{L}\p{N}]+@)?    optional email name
|                        OR a subdomain
   ([-.:\p{L}\p{N}]+@)?    optional email name
   [-\p{L}\p{N}]+\.        subdomain
)                        THAT'S WHAT INDICATES A URL
([-\p{L}\p{N}]+\.)*      optional extra subdomains
[\p{L}\p{N}]{2,}         top level domain
(:[0-9]+)?               optional port number
(                        optional path
   [\/?#]                  slash, question mark, or hash
   \S*                     optional non-whitespace characters
)?

*/
const slider = document.getElementById('num-slider');
const sliderMaxSetting = document.getElementById('posts');
const sliderMax = localStorage.getItem('max-posts');
if (sliderMax != null) {
  slider.setAttribute('max', sliderMax);
  sliderMaxSetting.setAttribute('value', sliderMax);
}
sliderMaxSetting.oninput = function() {
  slider.setAttribute('max', this.value);
  localStorage.setItem('max-posts', this.value);
}

let num = localStorage.getItem('num');
if (num != null) { slider.value = num; };

const number = document.getElementById('number');
number.innerHTML = slider.value;
slider.oninput = function() {
  number.innerHTML = this.value;
  localStorage.setItem('num', this.value);
}

// https://stackoverflow.com/a/14991797
async function parseCSV(str) {
  let last = null;

  let row = ['','',''], col = 0;
  let quote = false;  // 'true' means we're inside a quoted field

  // Iterate over each character
  for (let c = 0; c < str.length; c++) {
    let cc = str[c], nc = str[c+1];  // Current character, next character

    // If the current character is a quotation mark, and we're inside a
    // quoted field, and the next character is also a quotation mark,
    // add a quotation mark to the current column and skip the next character
    if (cc == '"' && quote && nc == '"') { row[col] += cc; ++c; continue; }

    // If it's just one quotation mark, begin/end quoted field
    if (cc == '"') { quote = !quote; continue; }

    // If it's a comma and we're not in a quoted field, move on to the next column
    if (cc == ',' && !quote) { ++col; continue; }

    // If it's a newline and we're not in a quoted field, display the current row, then
    // move on to the next row and move to column 0 of that new row
    if (cc == '\n' && !quote) {
      last = await addComment(row); row = ['','','']; col = 0; continue;
    }
    // Otherwise, append the current character to the current column
    row[col] += cc;
  }
  last = await addComment(row);
  document.getElementById('loader').remove();
  return last;
}
function reply(el) {
  comment.value += `>>${el.innerHTML.substring(4)}
`; // substring(4) removes the 'No. ' prefix
  comment.focus();
  comment.selectionStart = comment.value.length;
}

document.getElementById('test-image-btn').onclick = async function() {
  const url = document.getElementById('test-image').value;
  const imSize = await getImSize(url);
  if (imSize == -1) {
    document.getElementById('image-test-result').textContent = `Yes, ${url} can be embedded :)`;
  } else if (imSize > 0) {
    document.getElementById('image-test-result').textContent = `Yes, ${url} will be embedded for users with maxImageSize ≤ ${imSize/1000} KB`;
  } else {
    document.getElementById('image-test-result').textContent = `No, ${url} cannot be embedded :(`;
  }
}

const imagesMaxSetting = document.getElementById('images');
const imagesMax = localStorage.getItem('max-images');
if ( imagesMax != null) {
  maxImages = imagesMax;
  imagesMaxSetting.setAttribute('value', imagesMax);
}
imagesMaxSetting.oninput = function() {
  maxImages = this.value;
  localStorage.setItem('max-images', this.value);
}

const videosMaxSetting = document.getElementById('videos');
const videosMax = localStorage.getItem('max-videos');
if ( videosMax != null) {
  maxVideos = videosMax;
  videosMaxSetting.setAttribute('value', videosMax);
}
videosMaxSetting.oninput = function() {
  maxVideos = this.value;
  localStorage.setItem('max-videos', this.value);
}

const sizeMaxSetting = document.getElementById('size');
const sizeMax = localStorage.getItem('max-size');
if ( sizeMax != null) {
  maxSize = sizeMax;
  sizeMaxSetting.setAttribute('value', sizeMax);
}
sizeMaxSetting.oninput = function() {
  maxSize = this.value;
  localStorage.setItem('max-size', this.value);
}

document.getElementById('settings-icon').onclick = function() { document.getElementById('settings').style.display = 'block'; }
document.getElementById('close-settings').onclick = function() { document.getElementById('settings').style.display = 'none'; }

function toggle(el) {
  if (el.innerHTML === '▲') {
    el.innerHTML = '▼';
    el.nextSibling.style.display = 'none';
  } else {
    el.innerHTML = '▲';
    el.nextSibling.style.display = 'block';
  }
}

function redirect(id) {
  if (document.getElementById(id) == null) {
    window.location.href = `/?start=${id}#${id}`;
  } else {
    window.location.href = `#${id}`;
  }
}

let sqlStatement = encodeURIComponent(`select * where A is not null order by E desc limit ${Number(slider.value)}`);
let loaderPosition = 'afterend';
let start = window.location.toString().match(/start=([0-9]+)/);
if (start != null) {
  start = Number(start[1]);
  sqlStatement = encodeURIComponent(`select * where A is not null limit ${Number(slider.value)} offset ${start-1}`);
  desc = false;
  loaderPosition = 'beforebegin';
}
comments.insertAdjacentHTML(loaderPosition, '<div id="loader"></div>');
const csvUrl = `https://docs.google.com/spreadsheets/d/1krjuJMhr0NHwc2zHWRiVa1apy9fPlgNDfjZRjUq3yVU/gviz/tq?tqx=out:csv&sheet=comments&tq=${sqlStatement}&headers=0`;
fetch(csvUrl)
.then(response => response.text())
.then(csvText => parseCSV(csvText))
.then(lastAdded => {
  if (desc) { start = lastAdded; }
  if (start > 1) {
    for (const el of document.getElementsByClassName('next')) {
      el.style.display = 'block';
      el.addEventListener('click', (e) => { window.location.href = `/?start=${Math.max(start - Number(slider.value), 1)}`; });
    }
  }
  const targetId = window.location.toString().match(/#([0-9]+)/);
  if (targetId != null) { window.location.href = `#${targetId[1]}`; }
});
