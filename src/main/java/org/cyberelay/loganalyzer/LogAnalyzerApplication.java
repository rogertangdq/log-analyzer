package org.cyberelay.loganalyzer;

import com.google.common.collect.HashMultimap;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@SpringBootApplication
public class LogAnalyzerApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(LogAnalyzerApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		var options = new Options();
		var input = Option.builder("i")
				.longOpt("input")
				.desc("input log file path (default: log.csv)")
				.hasArg(true)
				//.required(true)
				.build();
		var output = Option.builder("o")
				.longOpt("output")
				.desc("output file path (default: output.txt)")
				.hasArg(true)
				//.required(true)
				.build();
		var lookup = Option.builder("l")
				.longOpt("lookup")
				.desc("lookup file path (default: lookup.csv)")
				.hasArg(true)
				//.required(true)
				.build();
		options.addOption(input).addOption(output).addOption(lookup);

		var parser = new DefaultParser();
		var formatter = new HelpFormatter();
		CommandLine cmd;

		try {
			cmd = parser.parse(options, args);
			String inputFilePath = cmd.getOptionValue("input", "log.txt");
			String outputFilePath = cmd.getOptionValue("output", "output.txt");
			String lookupFilePath = cmd.getOptionValue("lookup", "lookup.csv");
			var lookupTable = parseLookupTable(lookupFilePath);
			var collector = new LogStats(lookupTable);
			collectStats(inputFilePath, collector);
			collector.output(outputFilePath);
		} catch (ParseException e) {
			System.out.println(e.getMessage());
			formatter.printHelp("Log-analyzer", options);

			System.exit(1);
		}
	}

	private static void collectStats(String logFilePath, LogStats logStatsCollector) {
		try (Reader reader = new FileReader(logFilePath)) {
			CSVFormat.DEFAULT.builder()
					.setHeader()
					.setSkipHeaderRecord(true) // The header row is skipped
					.build()
					.parse(reader)
					.forEach(record -> {
						var port = Optional
								.ofNullable(record.get("dstport"))
								.orElseThrow(() -> new RuntimeException("dstport column not found in " + logFilePath));
						var protocol = Optional
								.ofNullable(record.get("protocol"))
								.orElseThrow(() -> new RuntimeException("protocol column not found in " + logFilePath));
						logStatsCollector.increment(new Socket(port, protocol));
					});
		} catch (Exception e) {
			throw new RuntimeException("Log file error: " + e.getMessage(), e);
		}
	}

	private static HashMultimap<Socket, String> parseLookupTable(String filePath) {
		HashMultimap<Socket, String> result = HashMultimap.create();

		try (Reader reader = new FileReader(filePath)) {
			CSVFormat.DEFAULT.builder()
					.setHeader()
					.setSkipHeaderRecord(true) // Optional: skip the header row
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

	record Socket(String port, String protocol) {}

	static class LogStats {
		final Map<Socket, Integer> statsBySocket;
		final Map<String, Integer> statsByTag;
		final HashMultimap<Socket, String> lookupTable;

		LogStats(HashMultimap<Socket, String> lookupTable) {
			this.statsBySocket = new HashMap<>();
			this.statsByTag = new HashMap<>();
			this.lookupTable = lookupTable;
		}

		void increment(Socket socket) {
			var socketCount = statsBySocket.computeIfAbsent(socket, key -> 0) + 1;
			statsBySocket.put(socket, socketCount);

			lookupTags(socket).forEach(tag -> {
				var count = statsByTag.computeIfAbsent(tag, key -> 0) + 1;
				statsByTag.put(tag, count);
			});
		}

		void output(String filePath) {
			try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
				// Write header 1
				writer.write(padString("Tag") + padString("Count") + "\n");

				statsByTag.forEach((tag, count) -> {
                    try {
                        writer.write(padString(tag) + padString(String.valueOf(count)) + "\n");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });

				writer.write("\n\n");
				// Write header 2
				writer.write(padString("Port") + padString("Protocol") + padString("Count") + "\n");

				statsBySocket.forEach((socket, count) -> {
					try {
						writer.write(padString(socket.port) + padString(socket.protocol) + padString(String.valueOf(count)) + "\n");
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
				});
			} catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

		private String padString(String input) {
			return StringUtils.rightPad(input, 15, ' ');
		}

		private Set<String> lookupTags(Socket key) {
			var tags = lookupTable.get(key);
			return tags.isEmpty() ? Set.of("untagged") : tags;
		}
	}
}
