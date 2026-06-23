# Replication Package

This repository contains the data and supporting materials for the article:

**Security and Reliability in the Robot Operating System: A Systematic Review from a Software Defects Perspective**

## Repository Structure

```text
data/
  excel/
    study_coding_workbook.xlsx
    review_defect_statistics.xlsx
  csv/
    study_coding_workbook/
    review_defect_statistics/
scripts/
  export_excel_to_csv.py
```

## Primary Replication Data

The primary replication data are provided in `data/csv/study_coding_workbook/`. These files contain the study-level coding results, defect evidence, coding framework, coding rules, inter-rater audit records, and agreement calculations used in the review.

| File                       | Description                                                                                                                                                      |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `01_Study_Coding.csv`      | Study-level coding data, including ROS version, assigned defect codes, quality-assessment fields, source-code requirements, simulation use, and tool support.    |
| `02_Defect_Evidence.csv`   | Evidence supporting each study–defect association, including coverage labels, evidence statements, evidence locations, impact categories, provenance, and notes. |
| `03_Codebook.csv`          | Definitions and operational criteria for the defect taxonomy and impact categories.                                                                              |
| `04_Coding_Rules.csv`      | Rules for coding ROS version, defect categories, source-code requirements, simulation use, and tool support.                                                     |
| `05_Coding_Audit.csv`      | Inter-rater audit records, including reviewer assignments, disagreements, and adjudicated labels.                                                                |
| `06_Kappa_Calculation.csv` | Cohen's kappa calculations for the validation sample.                                                                                                            |

The corresponding Excel workbook is available at:

```text
data/excel/study_coding_workbook.xlsx
```

## Statistical Results

The files in `data/csv/review_defect_statistics/` provide the aggregated statistics reported in the article.

| File                              | Description                                                                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `00_review_question_summary.csv`  | Summary of the main quantitative findings and the supporting statistical tables.                                                                  |
| `00b_readme.csv`                  | Counting rules, units of analysis, and definitions used in the statistical calculations.                                                          |
| `01_defect_code_counts.csv`       | Study counts, tool-supported counts, tool-support rates, source-code requirements, simulation use, and ROS-version coverage for each defect code. |
| `02_subcategory_summary.csv`      | Aggregated results by defect subcategory.                                                                                                         |
| `03_major_summary.csv`            | Aggregated results for vulnerability and reliability defects.                                                                                     |
| `04_tool_environment_summary.csv` | Summary of ROS version, source-code requirements, and simulation use across study groups.                                                         |
| `05_tool_ros_by_source.csv`       | Tool-supported studies by ROS version and source-code requirement.                                                                                |
| `06_tool_ros_by_simulation.csv`   | Tool-supported studies by ROS version and simulation-use category.                                                                                |
| `07_tool_source_by_sim.csv`       | Tool-supported studies by source-code requirement and simulation-use category.                                                                    |
| `08_simulation_only_tools.csv`    | Tool-supported studies evaluated only in simulation.                                                                                              |
| `08b_hybrid_tools.csv`            | Tool-supported studies evaluated using both simulation and non-simulation settings.                                                               |
| `09_source_required_tools.csv`    | Tool-supported studies requiring source-code access.                                                                                              |
| `09b_source_mixed_tools.csv`      | Tool-supported studies with mixed source-code requirements.                                                                                       |
| `10_ros2_only_tools.csv`          | Tool-supported studies applicable to ROS 2 but not ROS 1.                                                                                         |
| `11_low_tool_support_defects.csv` | Defect categories with absent or limited tool support.                                                                                            |
| `12_defect_tool_by_source.csv`    | Tool-supported studies by defect code and source-code requirement.                                                                                |
| `13_defect_tool_by_sim.csv`       | Tool-supported studies by defect code and simulation-use category.                                                                                |
| `14_defect_tool_by_ros.csv`       | Tool-supported studies by defect code and ROS version.                                                                                            |
| `15_expanded_study_defect.csv`    | Long-format data with one row for each study–defect association.                                                                                  |

The corresponding Excel workbook is available at:

```text
data/excel/review_defect_statistics.xlsx
```

## Regenerating the CSV Files

Install the required dependency:

```bash
python -m pip install openpyxl
```

Run the export script from the repository root:

```bash
python scripts/export_excel_to_csv.py
```

The script regenerates the CSV files from the Excel workbooks without modifying the underlying worksheet values.
