const fs = require("fs");
const html = fs.readFileSync("C:/temp/dashboard.html", "utf8");
fs.writeFileSync("public/index.html", html, {encoding: "utf8"});
console.log("Written:", html.length, "bytes");