import express from "express";
import path from "path";
import fs from "fs";
import router from "./routes";

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.json());

app.use((req, _res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
});

app.use("/api", router);

app.get("/", (_req, res) => {
  const filePath = path.resolve("public", "index.html");
  const html = fs.readFileSync(filePath, "utf8");
  res.setHeader("Content-Type", "text/html");
  res.send(html);
});

app.listen(PORT, () => {
  console.log(`AKR KeyGen API running on port ${PORT}`);
  console.log(`Developer Dashboard: http://localhost:${PORT}`);
});

export default app;