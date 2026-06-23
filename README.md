# Replication Package

This repository provides the replication data for the article:

**Security and Reliability in the Robot Operating System: A Systematic Review from a Software Defects Perspective**

## Repository Structure

```text
data/
  excel/
    review_defect_statistics.xlsx
    study_coding_workbook.xlsx
  csv/
    review_defect_statistics/
    study_coding_workbook/
scripts/
  export_excel_to_csv.py
```

## Excel Workbooks

| File | Purpose |
| --- | --- |
| `data/excel/review_defect_statistics.xlsx` | Statistics workbook summarizing defect counts, tool support, ROS-version coverage, source-code requirements, simulation use, and low-support defect categories. |
| `data/excel/study_coding_workbook.xlsx` | Main study-coding workbook. This is a renamed copy of the original file `final(4)_ALL_defect_compatible_工具标记111.xlsx`; the file name was simplified for GitHub readability, but the workbook content is unchanged. |

## CSV Files Exported From `review_defect_statistics.xlsx`

| CSV file | Purpose |
| --- | --- |
| `data/csv/review_defect_statistics/00_review_question_summary.csv` | High-level summary of reviewer-facing questions, direct statistics, interpretations, and the detailed sheet supporting each answer. |
| `data/csv/review_defect_statistics/00b_readme.csv` | Counting rules and basic metadata for the statistics workbook, including unit of analysis and tool-count definition. |
| `data/csv/review_defect_statistics/01_defect_code_counts.csv` | Per-defect-code study counts, tool-supported counts, tool-support rates, and breakdowns by source-code requirement, simulation use, and ROS version. |
| `data/csv/review_defect_statistics/02_subcategory_summary.csv` | Summary by major category and subcategory, including unique study counts, tool support, and study-defect instances. |
| `data/csv/review_defect_statistics/03_major_summary.csv` | Summary by major category, mainly vulnerability (`VUL`) versus reliability (`REL`) defects. |
| `data/csv/review_defect_statistics/04_tool_environment_summary.csv` | Counts by ROS version, source-code requirement, and simulation use across all studies, tool-supported studies, and non-tool studies. |
| `data/csv/review_defect_statistics/05_tool_ros_by_source.csv` | Cross-tabulation of tool-supported studies by ROS version and source-code requirement. |
| `data/csv/review_defect_statistics/06_tool_ros_by_simulation.csv` | Cross-tabulation of tool-supported studies by ROS version and simulation-use category. |
| `data/csv/review_defect_statistics/07_tool_source_by_sim.csv` | Cross-tabulation of tool-supported studies by source-code requirement and simulation-use category. |
| `data/csv/review_defect_statistics/08_simulation_only_tools.csv` | Tool-supported studies whose evaluation is coded as simulation-only. |
| `data/csv/review_defect_statistics/08b_hybrid_tools.csv` | Tool-supported studies whose evaluation combines simulation and non-simulation evidence. |
| `data/csv/review_defect_statistics/09_source_required_tools.csv` | Tool-supported studies whose method requires source code. |
| `data/csv/review_defect_statistics/09b_source_mixed_tools.csv` | Tool-supported studies with mixed source-code requirements. |
| `data/csv/review_defect_statistics/10_ros2_only_tools.csv` | Tool-supported studies coded as supporting ROS 2 but not ROS 1. |
| `data/csv/review_defect_statistics/11_low_tool_support_defects.csv` | Defect codes with absent or weak tool support. |
| `data/csv/review_defect_statistics/12_defect_tool_by_source.csv` | Per-defect-code cross-tabulation of tool-supported studies by source-code requirement. |
| `data/csv/review_defect_statistics/13_defect_tool_by_sim.csv` | Per-defect-code cross-tabulation of tool-supported studies by simulation-use category. |
| `data/csv/review_defect_statistics/14_defect_tool_by_ros.csv` | Per-defect-code cross-tabulation of tool-supported studies by ROS version. |
| `data/csv/review_defect_statistics/15_expanded_study_defect.csv` | Long-format table with one row per study-defect-code instance, used to trace aggregate counts back to individual study rows. |

## CSV Files Exported From `study_coding_workbook.xlsx`

| CSV file | Purpose |
| --- | --- |
| `data/csv/study_coding_workbook/01_Study_Coding.csv` | Main study-level coding table; one row corresponds to one included study and records ROS version, final defect codes, QA fields, source-code requirement, simulation use, and tool flag. |
| `data/csv/study_coding_workbook/02_Defect_Evidence.csv` | Defect-level evidence table linking studies to defect codes, coverage labels, evidence statements, evidence locations, impact categories, provenance, and notes. |
| `data/csv/study_coding_workbook/03_Codebook.csv` | Defect taxonomy and impact-code codebook, including category definitions, operational meanings, inclusion rules, exclusion rules, and typical evidence. |
| `data/csv/study_coding_workbook/04_Coding_Rules.csv` | Operational coding rules used to assign ROS version, defect category, defect code, source-code requirement, simulation use, and tool support. |
| `data/csv/study_coding_workbook/05_Coding_Audit.csv` | Inter-rater coding audit table showing reviewer codes, agreements/disagreements, and final adjudicated labels. |
| `data/csv/study_coding_workbook/06_Kappa_Calculation.csv` | Cohen's kappa calculation sheet for the validation sample, including agreement counts, observed agreement, expected agreement, and kappa values. |

## Reproduce the CSV Files

Install `openpyxl` if needed:

```bash
python -m pip install openpyxl
```

Then regenerate the CSV files:

```bash
python scripts/export_excel_to_csv.py
```

The CSV files are written as **UTF-8 with BOM** (`utf-8-sig`) so that Chinese text, en dashes, and the kappa symbol (`κ`) display correctly when opened in Microsoft Excel on Windows.

## Data Handling

The CSV files are direct worksheet exports from the two Excel workbooks. No values are manually retyped or edited during export. If either Excel workbook is updated, rerun `scripts/export_excel_to_csv.py` and commit the regenerated CSV files.
