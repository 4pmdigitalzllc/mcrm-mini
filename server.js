import express from "express";
import cors from "cors";
import helmet from "helmet";

const app = express();
app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "mcrm-mini", ts: Date.now() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("mcrm-mini listening on " + PORT));
