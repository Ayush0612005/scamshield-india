package io.scamshield.rag;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;

/**
 * Official advisories (data/advisories/*.md, front matter + body) chunked by paragraph and
 * embedded into pgvector at startup. Retrieval returns the top-k chunks with their source.
 */
@Service
public class AdvisoryStore implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdvisoryStore.class);

    public record Advisory(String title, String url, String publisher, String date, String text, double score) {
    }

    private final VectorStore vectorStore;
    private final Path dir;
    private final int topK;
    private volatile boolean ready;

    public AdvisoryStore(VectorStore vectorStore, @Value("${scamshield.advisories-dir}") String dir,
                         @Value("${scamshield.rag.top-k:4}") int topK) {
        this.vectorStore = vectorStore;
        this.dir = Path.of(dir);
        this.topK = topK;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            List<Document> docs = loadChunks(dir);
            List<String> ids = docs.stream().map(Document::getId).toList();
            try {
                vectorStore.delete(ids);
            } catch (RuntimeException ignored) {
                // first run: nothing to delete
            }
            vectorStore.add(docs);
            ready = true;
            log.info("Ingested {} advisory chunks from {}", docs.size(), dir.toAbsolutePath());
        } catch (Exception e) {
            log.warn("Advisory ingestion failed; continuing without RAG: {}", e.toString());
        }
    }

    public boolean isReady() {
        return ready;
    }

    public List<Advisory> search(String query) {
        if (!ready) {
            return List.of();
        }
        List<Document> hits = vectorStore.similaritySearch(SearchRequest.builder().query(query).topK(topK).build());
        List<Advisory> out = new ArrayList<>();
        for (Document d : hits) {
            Map<String, Object> m = d.getMetadata();
            out.add(new Advisory(str(m, "title"), str(m, "url"), str(m, "publisher"), str(m, "date"), d.getText(),
                    d.getScore() == null ? 0 : d.getScore()));
        }
        return out;
    }

    private static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? "" : v.toString();
    }

    static List<Document> loadChunks(Path dir) throws IOException {
        List<Document> docs = new ArrayList<>();
        try (Stream<Path> files = Files.list(dir)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".md")).sorted().toList()) {
                String raw = Files.readString(f, StandardCharsets.UTF_8).replace("\r\n", "\n");
                Map<String, String> meta = new LinkedHashMap<>();
                String body = raw;
                if (raw.startsWith("---\n")) {
                    int end = raw.indexOf("\n---\n", 4);
                    for (String line : raw.substring(4, end).split("\n")) {
                        int c = line.indexOf(':');
                        if (c > 0) {
                            meta.put(line.substring(0, c).trim(), line.substring(c + 1).trim());
                        }
                    }
                    body = raw.substring(end + 5);
                }
                int i = 0;
                for (String para : body.split("\n\\s*\n")) {
                    String t = para.strip();
                    if (t.length() < 40) {
                        continue;
                    }
                    Map<String, Object> md = new HashMap<>(meta);
                    md.put("source_file", f.getFileName().toString());
                    String id = UUID.nameUUIDFromBytes((f.getFileName() + "#" + i++).getBytes(StandardCharsets.UTF_8)).toString();
                    // the title is embedded with the chunk so retrieval matches on topic too
                    docs.add(new Document(id, meta.getOrDefault("title", "") + "\n" + t, md));
                }
            }
        }
        return docs;
    }
}
