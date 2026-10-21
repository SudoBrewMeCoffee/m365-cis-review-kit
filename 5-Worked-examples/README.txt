Add finished reviews here (report .docx + register .xlsx) so new reviewers can see what "done" looks like.
Finished reviews are client-confidential: keep them in your document library only, not in any copy of the kit sent outside, and never commit them to this repository.

SAMPLE-synthetic-* files are a made-up "ContosoTest" tenant used to test the scripts. They show what the collector's evidence file and the assessment's report draft look like, and can be used to try the assessment script without touching a real tenant:
  .\Invoke-M365CISAssessment.ps1 -EvidencePath ..\5-Worked-examples\SAMPLE-synthetic-evidence.json -ClientName ContosoTest
