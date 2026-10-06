from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np


class RAGEngine:
    def __init__(self):
        self.documents = []
        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.tfidf_matrix = None
        self._next_id = 1

    def add_document(self, title: str, content: str, classified: bool = False) -> int:
        doc = {
            "id": self._next_id,
            "title": title,
            "content": content,
            "classified": classified,
        }
        self.documents.append(doc)
        self._next_id += 1
        self._rebuild_index()
        return doc["id"]

    def _rebuild_index(self):
        if not self.documents:
            self.tfidf_matrix = None
            return
        corpus = [f"{d['title']} {d['content']}" for d in self.documents]
        self.tfidf_matrix = self.vectorizer.fit_transform(corpus)

    def search(self, query: str, top_k: int = 3) -> list:
        if not self.documents or self.tfidf_matrix is None:
            return []
        query_vec = self.vectorizer.transform([query])
        similarities = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        top_indices = np.argsort(similarities)[::-1][:top_k]
        results = []
        for idx in top_indices:
            if similarities[idx] > 0.0:
                results.append(
                    {**self.documents[idx], "relevance": float(similarities[idx])}
                )
        return results

    def list_documents(self) -> list:
        result = []
        for d in self.documents:
            if d.get("classified"):
                snippet = "[REDACTED — Classified. Access restricted to authorized personnel.]"
            else:
                snippet = d["content"][:150] + "..."
            result.append({"id": d["id"], "title": d["title"], "snippet": snippet})
        return result
