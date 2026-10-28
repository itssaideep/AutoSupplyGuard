# SBOM dataset replication package

The files in this package allows one to recreate the dataset and to perform all
the example analyses. First we present the **file structure** and then **how to
reconstruct the SBOM dataset**.

For the use case examples mentioned on the paper, please look at the Jupyter
Notebook `analysis/examples.ipynb`.

## File structure

After decompressing all \*.zstd files we will find the **initial state**. After
following all steps in the **how to reconstruct the SBOM dataset** section,
there will be the **final state** layout of files and directories.

### Initial state

The dataset package has the following files and directories:

```
drwxr-xr-x    7 nov.  20 19:38 analysis
drwxr-xr-x   18 nov.  20 10:27 sboms-compressed-files
drwxr-xr-x    2 oct.  01  2024 software
-rw-r--r-- 5,3K oct.  01  2024 clear-extensions.txt
-rw-r--r--   41 nov.  01  2024 regex-generic.txt
-rw-r--r--  12M nov.  23 12:08 sboms-01.csv
-rw-r--r-- 109M nov.  23 12:08 sboms-02-filenames.csv
-rw-r--r--  12G nov.  20 16:04 sboms-03-origins.csv
-rw-r--r-- 8,5M nov.  20 16:11 sboms-04-revisions.csv
```

Where:

- analysis - contains the jupyter notebook with the example analyses
- sboms-compressed-files - a directory with the gzip compressed SBOM files. Each
  filename is the SHA1 hash code of the uncompressed SBOM file. It is placed in
  a subdirectory named as the first character of the SHA1 code. Example: the
  file `bfef61c15c7fe513863c5ea053ce7a9715cc8784` is found at
  `sboms-compressed-files/b/bfef61c15c7fe513863c5ea053ce7a9715cc8784`
- software - all the software programs that were developed for the creation of
  this dataset. They are in Java, Python and Bash.
- clear-extensions.txt - the list of extensions of known SBOM files
- sboms-01.csv - table with the fields
  sha1,sha1_git,swhid,score,standard,version,format
- sboms-02-filenames.csv - table with the fields sha1,filename (one entry for
  each filename found for each sbom file)
- sboms-03-origins.csv - table with the fields swhid,origin_url (one entry for
  each origin where the sbom file was found)
- sboms-04-revisions.csv - table with the fields
  swhid,earliest_swhid,earliest_ts,rev_occurrences. earliest_swhid: the SWHID of
  the earliest revision (commit) found that included the SBOM file; earliest_ts:
  the earliest timestamp for when that SBOM file was observed; rev_occurrences:
  the total number of revisions that were found that contained that SBOM file.

### Final state

After performing the replication steps, there will also be intermediate files
(`files-*`) and directories (`candidate-files`, `content`, `directory_entry`):

```
drwxr-xr-x    7 nov.  20 19:38 analysis
drwxr-xr-x   18 oct.  16 14:32 candidate-files
drwxr-xr-x   18 oct.  01 14:32 content
drwxr-xr-x   18 oct.  01 14:32 directory_entries
drwxr-xr-x   18 nov.  20 10:27 sboms-compressed-files
drwxr-xr-x    2 oct.  01  2024 software
-rw-r--r-- 5,3K oct.  01  2024 clear-extensions.txt
-rw-r--r--   41 nov.  01  2024 regex-generic.txt
-rw-r--r--  82G oct.  14 17:54 files-01-spark.csv
-rw-r--r-- 5,9G oct.  14 21:35 files-02-deduplicated.csv
-rw-r--r-- 3,8G oct.  25 19:22 files-03-cleared.csv
-rw-r--r-- 3,8G oct.  16 11:47 files-04-shuffled.csv
-rw-r--r-- 3,2G nov.  20 11:19 files-05-evaluations.csv
-rw-r--r--  150 oct.  24 21:34 files-05-evaluations.csv.log
-rw-r--r-- 9,0M nov.  20 12:49 files-06-sboms-raw-results.csv
-rw-r--r-- 4,4M nov.  20 14:43 files-07-sboms-results.csv
-rw-r--r--  12M nov.  23 12:08 sboms-01.csv
-rw-r--r-- 109M nov.  23 12:08 sboms-02-filenames.csv
-rw-r--r--  12G nov.  20 16:04 sboms-03-origins.csv
-rw-r--r-- 8,5M nov.  20 16:11 sboms-04-revisions.csv

```

Where, in addition to the previous listing, it contains:

- candidate-files - all the gzip compressed files that were downloaded from S3.
  The filename is the SHA1 hash code of its uncompressed content and it is
  listed in the filed 'sha1` of all the csv tables.
- content - contains all the Optimized Row Columnar (ORC) files that map SBOM
  file's hashcodes: sha1, sha1_git, and swhid.
- directory_entries - contains all the Optimized Row Columnar (ORC) files that
  store either a directory entry or filename in the Software Heritage Archive.
- files-01-\* to files-07-\* are the intermediate tables of the described steps;

## How to reconstruct the SBOM Dataset

We present a series of steps to reconstruct the dataset. It's important to note
that there are some parts that require access to large amounts of RAM (~512GB
RAM and ~2TB RAM) and storage space (~14TB).

We present 9 steps.

### 1. Download of indexes

We need to download the `content` and the `directory_entry` folders from the
SOftware Heritage archive at Amazon's S3. This will allow us to load those ORC
files into Spark and run a query on the filenames.

The commands are:

- List files:

```
aws --no-sign-request s3 ls s3://softwareheritage/graph/2024-08-23/orc/
```

- Copy recursively:

```
aws --no-sign-request s3 cp --recursive s3://softwareheritage/graph/2024-08-23/orc/directory_entry .
```

and

```
aws --no-sign-request s3 cp --recursive s3://softwareheritage/graph/2024-08-23/orc/content .
```

### 2. Filter for filenames

This step we just make sure to add the filter for files only, so that the total
amount of time and RAM required are reduced.

This line should be present in the Java program:
'''
Dataset<Row> matchingRows = directoryEntries.where(directoryEntries.col("type").equalTo("file").and(rlike0.or(rlike1)));
'''

### 3. Search for regular expressions:

This step requires at least 512GB RAM available.

After getting the necessary ORC files, we run an Apache Spark query using the
Java utility that we've developed.

```
search-for-sboms.sh -d directory_entry/ -m content/ -r regex-generic.txt -s sboms-01-spark.csv
```


### 4. Deduplication of findings:

The output of the initial query on Spark may have repeated rows, because the
same sbom file maybe be present (e.g., commits, forks, import) in other origins.
We need to remove duplicates. For that we use the following commands:

```
$ sort files-01-spark.csv | uniq > files-02-deduplicated.csv
```

### 5. Removal of records with non-SBOM file extensions

We need to remove the candidates that have extensions that are known to be not
used for SBOMs.

Initial set: 37 036 597 files After removing known extensions, there were: 23
590 859 SBOM files

```
$ cat files-02-deduplicated.csv | clear-extensions.sh -e ~/bin/clear-extensions.txt > files-03-cleared.csv
There were 991 unique extensions read.
There were 13445737 removed lines
Extensions that matched, by matches:
.html: 2752076
.png: 1890868
.md: 1174887
.java: 1164372
.sql: 846543
.js: 840837
.cpp: 597208
.jpg: 594712
.h: 452989
.csv: 290942
.dxf: 217712
.c: 196783
.pdf: 145551
[...]
.xwd: 1
.yin: 1

```

### 6. Download and evaluation of candidate SBOM files:

#### Download

Now we download all candidate SBOM files from S3. In order to distribute the
load better, we shuffle the list of files to download:

Copy just the CSV header:

```
$ head -n 1 files-03-cleared.csv > files-04-shuffled.csv
```

Shuffle the contents without the header:

```
$ tail -n +2 files-03-cleared.csv |shuf >> files-04-shuffled.csv
```

Now, we download all files from S3, placing them in the `candidate-files`
directory. Note that `range.txt` is optional. When present it indicates what
range of files each host will download. The idea is to use many hosts to spread
the download effort.

```
$ download-all.sh files-04-shuffled.csv candidate-files [range.txt]
```

After downloading the files, which might take a long time, it is important to
verify if they are correct and decide if it is worthwhile to try to downloadtar
c --zstd -f ../sbom-files.tar.ztsd sbom-files corrupted or missing files.

```
$ verify-all.sh source_dir output_report.csv [range.txt]
```

#### Evaluation

We evaluate the candidate files using the sbomqs tool. In our server it requires
just under 3 hours to complete.

```
evaluate-all.sh files-04-shuffled.csv candidate-files sboms-evaluation.csv sboms-compressed-files
```

All files that don't fail the test are copied do the `sboms-compressed-files`
directory. The complete report is in the file `files-05-evaluations.csv`.

After the evaluation run, it is necessary to perform a clean up of the
`files-05-evaluations.csv` file. We copy all lines that don't have the 'failed'
message, sorting then and removing duplicates (e.g., resulting for reruns):

```
grep -v -i "failed" files-05-evaluations.csv |sort|uniq > files-06-sboms-raw-results.csv
```

Now the file `files-06-sboms-raw-results.csv` lists in the first column the sha1
of the content of the SBOM files when decompressed and also the gziped SBOM
filename.

Now we parse the results columns into new columns to generate the
`files-07-sboms.csv` file. For this we execute the script:

```
$ interpret-evaluations.py
```

### 7. Metadata addition

**Note**: we've observed that This step has used ~1.4TB of RAM.

After getting the list of SHA1s of real SBOM files, we need to get the SWHIDs
and SHA1_git codes from the file that was generated by the Java search program.

We join the `files-07-sboms.csv` table with the `files-03-cleared.csv` table.

We select only sha1,filename fields and remove all duplicates. Then we export
the result as `sboms-02-filenames.csv`.

We then drop all rows that have duplicate `sha1` values, then select only the
fields `sha1,sha1_git,swhid,score,standard,version,format`, and export the
result as `sboms-01.csv`.

The script `join-and-extract.py` does it (modify the desired parameters inside
the script).

Follow instruction on https://docs.softwareheritage.org/devel/getting-started/
to prepare the environment, including the dependencies.

We need to have the Software Heritage Graph for the appropriate release, in this
case 2024-08-23. With the Software Heritage compressed graph installed and
instantiated, run:

```
$ get-origins-all.sh sboms-01.csv sboms-03-origins.csv
```

Now to get the revisions, it is necessary to get a rust program from from the
software heritage development environment. Clone the repository:

```
~ $ git clone https://gitlab.softwareheritage.org/swh/devel/swh-graph.git
```

Change to the specified commit (the version used for the paper):

```
~ $ cd swh-graph
~/swh-graph $ git checkout f101d652d046aee250e5eadfa6350d2109bc88ac
```

Build the tools:

```
~/swh-graph $ cargo build

```

Run the tool to get the revisions (the third field is 'shwid'):

```
~ $ cat sboms-01.csv | cut -d ',' -f 3 | find-earliest-revision path/to/graph > sboms-04-revisions.csv

```
