/* ============================================================
   ml.js — Integração com a API oficial do Mercado Livre
   Versão 6 — tendências com produto + preço
   ============================================================ */
"use strict";
const fs = require("fs");
const path = require("path");

const CLIENT_ID = process.env.ML_CLIENT_ID || "5882584876609918";
const CLIENT_SECRET = process.env.ML_CLIENT_SECRET || "U7gXTzjliVLHybL0w0UsfoBNBrtO24Zl";

module.exports = function criarML(dataDir) {
  const ARQ = path.join(dataDir, "ml-token.json");
  const CACHE_TRENDS = path.join(dataDir, "ml-trends.json");
  const CACHE_CATS = path.join(dataDir, "ml-cats.json");

  const estado = {
    access_token: process.env.ML_ACCESS_TOKEN || "",
    refresh_token: process.env.ML_REFRESH_TOKEN || "",
    expires_at: 0,
    renovando: null,
  };

  try {
    if (fs.existsSync(ARQ)) {
      const salvo = JSON.parse(fs.readFileSync(ARQ, "utf8"));
      if (salvo.access_token) estado.access_token = salvo.access_token;
      if (salvo.refresh_token) estado.refresh_token = salvo.refresh_token;
      if (salvo.expires_at) estado.expires_at = salvo.expires_at;
      if (Date.now() > estado.expires_at - 300000 && estado.refresh_token) {
        renovar().catch(() => {});
      }
    }
  } catch (_) {}

  function salvarToken() {
    try {
      fs.writeFileSync(ARQ, JSON.stringify({
        access_token: estado.access_token,
        refresh_token: estado.refresh_token,
        expires_at: estado.expires_at,
      }, null, 2));
    } catch (_) {}
  }

  async function renovar() {
    if (estado.renovando) return estado.renovando;
    if (!estado.refresh_token) return false;
    estado.renovando = (async () => {
      try {
        const body = new URLSearchParams({
          grant_type: "refresh_token",
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          refresh_token: estado.refresh_token,
        });
        const r = await fetch("https://api.mercadolibre.com/oauth/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
          },
          body,
        });
        if (!r.ok) { console.error("[ML] Falha ao renovar token:", r.status); return false; }
        const j = await r.json();
        estado.access_token = j.access_token;
        estado.refresh_token = j.refresh_token || estado.refresh_token;
        estado.expires_at = Date.now() + (j.expires_in || 21600) * 1000;
        salvarToken();
        console.log("[ML] Token renovado. Expira em", new Date(estado.expires_at).toLocaleString("pt-BR"));
        return true;
      } catch (e) { console.error("[ML] Erro ao renovar:", e.message); return false; }
      finally { estado.renovando = null; }
    })();
    return estado.renovando;
  }

  async function chamar(url, semToken) {
    if (!estado.access_token && estado.refresh_token) await renovar();
    if (Date.now() > estado.expires_at - 300000 && estado.refresh_token) await renovar();

    const headers = { "Accept": "application/json" };
    if (!semToken) headers["Authorization"] = "Bearer " + estado.access_token;

    const r1 = await fetch(url, { headers });
    if (r1.status === 401 && !semToken && estado.refresh_token) {
      const ok = await renovar();
      if (ok) {
        return fetch(url, {
          headers: {
            "Authorization": "Bearer " + estado.access_token,
            "Accept": "application/json",
          },
        });
      }
    }
    return r1;
  }

  function lerCache(arq, maxHoras) {
    try {
      if (!fs.existsSync(arq)) return null;
      const j = JSON.parse(fs.readFileSync(arq, "utf8"));
      if (!j.ts || Date.now() - j.ts > maxHoras * 3600000) return null;
      return j.dados;
    } catch (_) { return null; }
  }
  function salvarCache(arq, dados) {
    try { fs.writeFileSync(arq, JSON.stringify({ ts: Date.now(), dados }, null, 2)); } catch (_) {}
  }

  // Busca detalhes de um produto do catálogo
  async function detalharProduto(produtoId) {
    try {
      const rp = await chamar("https://api.mercadolibre.com/products/" + produtoId);
      if (!rp.ok) return null;
      const p = await rp.json();

      let preco = null, permalink = null, vendidos = null, estoque = null, itemId = null;
      const ri = await chamar("https://api.mercadolibre.com/products/" + produtoId + "/items?limit=1");
      if (ri.ok) {
        const ji = await ri.json();
        const resultados = ji.results || ji.items || [];
        if (resultados.length > 0) {
          const it = resultados[0];
          itemId = it.id;
          preco = it.price != null ? it.price : null;
          permalink = it.permalink || null;
          vendidos = it.sold_quantity != null ? it.sold_quantity : null;
          estoque = it.available_quantity != null ? it.available_quantity : null;
        }
      }
      if (preco == null && p.buy_box_winner) {
        preco = p.buy_box_winner.price != null ? p.buy_box_winner.price : null;
        if (!permalink) permalink = p.buy_box_winner.permalink || null;
        if (vendidos == null) vendidos = p.buy_box_winner.sold_quantity != null ? p.buy_box_winner.sold_quantity : null;
      }
      if (preco == null && itemId) {
        const rit = await chamar("https://api.mercadolibre.com/items/" + itemId);
        if (rit.ok) {
          const it = await rit.json();
          preco = it.price != null ? it.price : null;
          permalink = permalink || it.permalink || null;
          vendidos = vendidos != null ? vendidos : (it.sold_quantity != null ? it.sold_quantity : null);
          estoque = estoque != null ? estoque : (it.available_quantity != null ? it.available_quantity : null);
        }
      }
      const foto = (p.pictures && p.pictures[0] && (p.pictures[0].secure_url || p.pictures[0].url)) || null;
      return {
        id: p.id,
        titulo: p.name || p.title || p.id,
        preco: preco,
        moeda: p.currency_id || "BRL",
        permalink: permalink || ("https://www.mercadolivre.com.br/p/" + p.id),
        foto: foto,
        vendidos: vendidos,
        estoque: estoque,
      };
    } catch (e) {
      console.error("[ML] erro ao detalhar produto", produtoId, e.message);
      return null;
    }
  }

  // --- Tendências: termo + produto real (foto, nome, preço) ---
  async function getTrends() {
    const cache = lerCache(CACHE_TRENDS, 6);
    if (cache) return cache;

    const r = await chamar("https://api.mercadolibre.com/trends/MLB");
    if (!r.ok) throw new Error("ML respondeu " + r.status);
    const termos = await r.json();
    if (!Array.isArray(termos)) return [];

    // Pra cada termo, busca o produto mais vendido relacionado
    const limite = Math.min(termos.length, 30);
    const resultado = [];
    for (let i = 0; i < limite; i += 4) {
      const lote = termos.slice(i, i + 4);
      const promessas = lote.map(async (t) => {
        const kw = t.keyword || t.title || "";
        if (!kw) return { keyword: "", produto: null };
        try {
const url = "https://api.mercadolibre.com/products/search?status=active&site_id=MLB&q=" + encodeURIComponent(kw) + "&limit=3";
         const rs = await chamar(url);
          if (!rs.ok) return { keyword: kw, produto: null };
          const j = await rs.json();
const resultados = j.results || [];
if (!resultados.length) return { keyword: kw, produto: null };
const p = resultados[0];
const item = (p.buy_box_winner) || {};
const preco = item.price != null ? item.price : (p.price != null ? p.price : null);
const foto = (p.pictures && p.pictures[0] && (p.pictures[0].secure_url || p.pictures[0].url)) || null;
return {
  keyword: kw,
  produto: {
    id: p.id,
    titulo: p.name || p.title || p.id,
    preco: preco,
    moeda: "BRL",
    permalink: p.permalink || ("https://www.mercadolivre.com.br/p/" + p.id),
    foto: foto,
    vendidos: item.sold_quantity != null ? item.sold_quantity : null,
  }
};
        } catch (e) {
          return { keyword: kw, produto: null };
        }
      });
      const resolvidos = await Promise.all(promessas);
      resultado.push(...resolvidos);
    }

    salvarCache(CACHE_TRENDS, resultado);
    return resultado;
  }

  async function getCategories() {
    const cache = lerCache(CACHE_CATS, 168);
    if (cache) return cache;
    const r = await chamar("https://api.mercadolibre.com/sites/MLB/categories");
    if (!r.ok) throw new Error("ML respondeu " + r.status);
    const j = await r.json();
    const dados = Array.isArray(j) ? j.map(c => ({ id: c.id, name: c.name })) : [];
    salvarCache(CACHE_CATS, dados);
    return dados;
  }

  async function getHighlights(cat) {
    const c = String(cat || "").replace(/[^A-Z0-9]/g, "");
    if (!c) throw new Error("Categoria inválida");
    const cacheKey = path.join(dataDir, "ml-top-" + c + ".json");
    const cache = lerCache(cacheKey, 3);
    if (cache) {
      console.log("[ML] Cache hit para", c, "—", cache.length, "itens");
      return cache;
    }

    const urlHl = "https://api.mercadolibre.com/highlights/MLB/category/" + c;
    console.log("[ML] Buscando IDs:", urlHl);
    let r = await chamar(urlHl);
    console.log("[ML] Resposta /highlights:", r.status);

    let refs = [];
    if (r.ok) {
      const j = await r.json();
      const lista = Array.isArray(j) ? j : (j.content || j.items || []);
      refs = lista.slice(0, 20).map(x => {
        const tipo = (x.type || "").toUpperCase();
        const id = x.id || (x.item && x.item.id) || "";
        return { tipo, id };
      }).filter(x => x.id);
      console.log("[ML] IDs encontrados:", refs.length);
    }

    const produtos = [];
    for (let i = 0; i < refs.length; i += 6) {
      const lote = refs.slice(i, i + 6);
      const promessas = lote.map(async (x) => {
        if (x.tipo === "PRODUCT" || /^MLB\d+$/.test(x.id)) {
          const det = await detalharProduto(x.id);
          if (det) return det;
        }
        try {
          const ri = await chamar("https://api.mercadolibre.com/items/" + x.id);
          if (ri.ok) {
            const it = await ri.json();
            return {
              id: it.id,
              titulo: it.title || it.id,
              preco: it.price != null ? it.price : null,
              moeda: it.currency_id || "BRL",
              permalink: it.permalink || ("https://www.mercadolivre.com.br/p/" + it.id),
              foto: (it.pictures && it.pictures[0] && it.pictures[0].secure_url) || it.thumbnail || null,
              vendidos: it.sold_quantity != null ? it.sold_quantity : null,
              estoque: it.available_quantity != null ? it.available_quantity : null,
            };
          }
        } catch (_) {}
        return { id: x.id, titulo: x.id, preco: null, permalink: null, foto: null };
      });
      const resolvidos = await Promise.all(promessas);
      produtos.push(...resolvidos.filter(Boolean));
    }

    console.log("[ML] Total detalhado:", produtos.length);

    if (produtos.length > 0) {
      salvarCache(cacheKey, produtos);
      return produtos;
    }

    console.warn("[ML] Nada para", c);
    return [];
  }

  async function handle(req, res, p, url, send) {
    if (req.method !== "GET" || !p.startsWith("/api/ml/")) return false;

    if (p === "/api/ml/trends") {
      try { send(res, 200, await getTrends()); }
      catch (e) { console.error("[ML] /trends erro:", e.message); send(res, 500, { error: e.message }); }
      return true;
    }
    if (p === "/api/ml/highlights") {
      try { send(res, 200, await getHighlights(url.searchParams.get("cat"))); }
      catch (e) { console.error("[ML] /highlights erro:", e.message); send(res, 500, { error: e.message }); }
      return true;
    }
    if (p === "/api/ml/categories") {
      try { send(res, 200, await getCategories()); }
      catch (e) { console.error("[ML] /categories erro:", e.message); send(res, 500, { error: e.message }); }
      return true;
    }
    return false;
  }

  return { handle, renovar, getTrends, getHighlights, getCategories, estado };
};