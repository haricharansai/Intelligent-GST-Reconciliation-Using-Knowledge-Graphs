import os
import json
import csv
from io import StringIO
from typing import List, Dict, Optional
import networkx as nx
import pickle

from datetime import datetime


class GraphManager:
    """Builds a simple knowledge graph from GST upload files.

    Nodes: Business (gstin), Invoice (invoice_no), File (uploaded file)
    Edges: REPORTED_IN (Business -> Invoice), FROM_FILE (File -> Invoice), SAME_INVOICE (Invoice <-> Invoice)
    """

    def __init__(self, db_session, user_id: int, upload_root: str = "uploads"):
        self.db = db_session
        self.user_id = int(user_id)
        self.upload_root = upload_root
        self.G = nx.DiGraph()

    def _read_rows_from_file(self, uploaded_file) -> List[Dict]:
        """Open the stored file_path and return list of row dicts for CSV/JSON."""
        path = uploaded_file.file_path
        if not path or not os.path.isfile(path):
            return []

        lower = path.lower()
        try:
            if lower.endswith(".csv"):
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    reader = csv.DictReader(fh)
                    return [r for r in reader]

            if lower.endswith(".json"):
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                    if isinstance(data, list):
                        return [r for r in data if isinstance(r, dict)]
                    return []

            # Excel not fully supported here
            return []
        except Exception:
            return []

    def build_graph(self, upload_ids: Optional[List[int]] = None) -> Dict:
        """Build graph from UploadedFile rows for current user.

        If upload_ids provided, only include those uploads; otherwise include all uploads for user.
        """
        # import lazily to avoid circular issues when used from main
        UploadedFile = None
        try:
            from main import UploadedFile as UF
            UploadedFile = UF
        except Exception:
            # Fallback: query by table name using SQL directly
            UploadedFile = None

        q = self.db.query if hasattr(self.db, "query") else None
        files = []
        if q is not None:
            if upload_ids:
                files = q(UploadedFile).filter(UploadedFile.user_id == self.user_id, UploadedFile.id.in_(upload_ids)).all()
            else:
                files = q(UploadedFile).filter(UploadedFile.user_id == self.user_id).all()

        invoices_index = {}

        for f in files:
            file_node = f"file:{f.id}"
            self.G.add_node(file_node, type="file", id=f.id, filename=f.filename, file_type=f.file_type)

            rows = self._read_rows_from_file(f)
            for r in rows:
                # Normalize common fields
                gstin = (r.get("gstin") or r.get("supplier_gstin") or r.get("buyer_gstin") or r.get("gstin_no") or "").strip()
                invoice_no = (r.get("invoice_no") or r.get("inv_no") or r.get("invoiceNumber") or r.get("invoice") or "").strip()
                invoice_date = r.get("invoice_date") or r.get("inv_date") or r.get("date") or None
                taxable = float(r.get("taxable_value") or r.get("taxable") or r.get("taxableamount") or 0 or 0)
                total_gst = float(r.get("total_gst") or r.get("gst") or r.get("tax") or 0 or 0)

                if not invoice_no:
                    # skip rows without invoice identifier
                    continue

                inv_node = f"invoice:{f.id}:{invoice_no}"
                # If an invoice node with same invoice_no already exists, link them
                if invoice_no in invoices_index:
                    for existing in invoices_index[invoice_no]:
                        self.G.add_edge(existing, inv_node, relation="same_invoice")
                        self.G.add_edge(inv_node, existing, relation="same_invoice")
                    invoices_index[invoice_no].append(inv_node)
                else:
                    invoices_index[invoice_no] = [inv_node]

                self.G.add_node(inv_node, type="invoice", invoice_no=invoice_no, invoice_date=invoice_date,
                                taxable_value=taxable, total_gst=total_gst, source_file=f.id)

                # Attach file -> invoice
                self.G.add_edge(file_node, inv_node, relation="from_file")

                # Attach business -> invoice
                if gstin:
                    bus_node = f"business:{gstin}"
                    if not self.G.has_node(bus_node):
                        self.G.add_node(bus_node, type="business", gstin=gstin)
                    self.G.add_edge(bus_node, inv_node, relation="reported_in")

        # Save graph pickle for this user
        out_dir = os.path.join(self.upload_root, str(self.user_id))
        os.makedirs(out_dir, exist_ok=True)
        pkl_path = os.path.join(out_dir, "graph.pkl")
        try:
            with open(pkl_path, "wb") as fh:
                pickle.dump(self.G, fh)
        except Exception:
            pass

        return {"nodes": self.G.number_of_nodes(), "edges": self.G.number_of_edges(), "files_processed": len(files)}

    def detect_mismatches(self, tolerance_pct: float = 10.0) -> Dict:
        """Simple mismatch detection across invoices with same invoice_no reported in different files.

        Returns list of invoices where total_gst differs more than tolerance_pct.
        """
        results = []
        # Group invoice nodes by invoice_no
        invoices = [n for n, d in self.G.nodes(data=True) if d.get("type") == "invoice"]
        by_no = {}
        for n in invoices:
            data = self.G.nodes[n]
            inv_no = data.get("invoice_no")
            by_no.setdefault(inv_no, []).append((n, data))

        for inv_no, items in by_no.items():
            if len(items) < 2:
                continue
            # compare totals pairwise
            base = items[0][1].get("total_gst") or 0.0
            for node, data in items[1:]:
                other = data.get("total_gst") or 0.0
                diff = abs(base - other)
                pct = (diff / base * 100.0) if base else (100.0 if other else 0.0)
                if pct > tolerance_pct:
                    results.append({
                        "invoice_no": inv_no,
                        "node_a": items[0][0],
                        "a_total_gst": base,
                        "node_b": node,
                        "b_total_gst": other,
                        "pct_diff": round(pct, 2),
                    })

        return {"count": len(results), "mismatches": results}

    def load_graph(self) -> bool:
        out_dir = os.path.join(self.upload_root, str(self.user_id))
        pkl_path = os.path.join(out_dir, "graph.pkl")
        if not os.path.isfile(pkl_path):
            return False
        try:
            with open(pkl_path, "rb") as fh:
                self.G = pickle.load(fh)
            return True
        except Exception:
            return False
