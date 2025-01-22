package org.cyberelay.loganalyzer;

import com.google.common.collect.HashMultimap;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.lang3.StringUtils;

import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class LogStatsCollector {
    private record Socket(String port, String protocol) {}

    private class Stats {
        final Map<Socket, Integer> statsBySocket = new HashMap<>();
        final Map<String, Integer> statsByTag = new HashMap<>();

        void increment(Socket socket) {
            var socketCount = statsBySocket.computeIfAbsent(socket, key -> 0) + 1;
            statsBySocket.put(socket, socketCount);

            lookupTags(socket).forEach(tag -> {
                var count = statsByTag.computeIfAbsent(tag, key -> 0) + 1;
                statsByTag.put(tag, count);
            });
        }
    }

    private final HashMultimap<Socket, String> lookupTable;

    public LogStatsCollector(String lookupFilePath) {
        this.lookupTable = parseLookupTable(lookupFilePath);
    }

    public void collect(String inputPath, String outputPath) {
        var stats = collectStats(inputPath);

        // For debug purpose. It should be replaced with logging
        System.out.println("Writing into output file: " + outputPath);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            // Write header for Segment 1
            writeline(writer, "Tag", "Count");
            // Write data for Segment 1
            stats.statsByTag.forEach((tag, count) -> writeline(writer, tag, String.valueOf(count)));

            // Write an empty line as a separator between the first and second segment
            writeline(writer,"");

            // Write header for Segment 2
            writeline(writer, "Port", "Protocol", "Count");
            // Write data for Segment 2
            stats.statsBySocket.forEach((socket, count) -> writeline(writer, socket.port, socket.protocol, String.valueOf(count)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void writeline(BufferedWriter writer, String... columns) {
        try {
            var line = Arrays.stream(columns).map(this::padString).collect(Collectors.joining());
            writer.write(line);
            writer.write("\n");

            // For debug purpose. It should be replaced with logging
            System.out.println(line);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Stats collectStats(String logFilePath) {
        // For debug purpose. It should be replaced with logging
        System.out.println("Parsing log file: " + logFilePath);
        var result = new Stats();
        try (Reader reader = new FileReader(logFilePath)) {
            CSVFormat.DEFAULT.builder()
                    .setHeader()
                    .setSkipHeaderRecord(true) // The header row is skipped
                    .setIgnoreHeaderCase(true)
                    .build()
                    .parse(reader)
                    .forEach(record -> {
                        var port = Optional
                                .ofNullable(record.get("dstport"))
                                .orElseThrow(() -> new RuntimeException("dstport column not found in " + logFilePath));
                        var protocol = Optional
                                .ofNullable(record.get("protocol"))
                                .orElseThrow(() -> new RuntimeException("protocol column not found in " + logFilePath));
                        result.increment(new Socket(port, protocol));
                    });
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Log file error: " + e.getMessage(), e);
        }
    }

    private HashMultimap<Socket, String> parseLookupTable(String filePath) {
        // For debug purpose. It should be replaced with logging
        System.out.println("Parsing lookup file: " + filePath);
        HashMultimap<Socket, String> result = HashMultimap.create();

        try (Reader reader = new FileReader(filePath)) {
            CSVFormat.DEFAULT.builder()
                    .setHeader()
                    .setSkipHeaderRecord(true) // Optional: skip the header row
                    .setIgnoreHeaderCase(true)
                    .build()
                    .parse(reader)
                    .forEach(record -> {
                        var port = Optional
                                .ofNullable(record.get("dstport"))
                                .orElseThrow(() -> new RuntimeException("dstport column not found in " + filePath));
                        var protocol = Optional
                                .ofNullable(record.get("protocol"))
                                .orElseThrow(() -> new RuntimeException("protocol column not found in " + filePath));
                        var tag = Optional
                                .ofNullable(record.get("tag"))
                                .orElseThrow(() -> new RuntimeException("tag column not found in " + filePath));
                        var entry = new Socket(port, protocol);

                        result.put(entry, tag);
                    });
        } catch (Exception e) {
            throw new RuntimeException("Lookup table file error: " + e.getMessage(), e);
        }

        return result;
    }

    private String padString(String input) {
        return StringUtils.rightPad(input, 15, ' ');
    }

    private Set<String> lookupTags(Socket socket) {
        var tags = lookupTable.get(socket);
        return tags.isEmpty() ? Set.of("untagged") : tags;
    }
}
