require([
  "jquery",
  "splunkjs/mvc/simplexml/ready!"
], function($) {
  function panelRoot() {
    return $(".dashboard-row").filter(function() {
      return $(this).find(".panel-head h3").text().indexOf("End-of-Shift Handoff Report") >= 0;
    }).first();
  }

  function readHandoffTable() {
    var $panel = panelRoot();
    if (!$panel.length) {
      return { headers: [], rows: [] };
    }

    var $table = $panel.find("table.dataTable, table.table, table").first();
    if (!$table.length) {
      return { headers: [], rows: [] };
    }

    var headers = [];
    $table.find("thead th").each(function() {
      headers.push($.trim($(this).text()));
    });

    if (!headers.length) {
      $table.find("tr:first td").each(function() {
        headers.push($.trim($(this).text()));
      });
    }

    var rows = [];
    $table.find("tbody tr").each(function() {
      var row = [];
      $(this).find("td").each(function() {
        row.push($.trim($(this).text()));
      });
      if (row.length) {
        rows.push(row);
      }
    });

    return { headers: headers, rows: rows };
  }

  function csvEscape(value) {
    var text = value == null ? "" : String(value);
    if (text.indexOf('"') >= 0 || text.indexOf(",") >= 0 || text.indexOf("\n") >= 0) {
      return '"' + text.replace(/"/g, '""') + '"';
    }
    return text;
  }

  function tableToCsv(data) {
    var lines = [];
    if (data.headers.length) {
      lines.push(data.headers.map(csvEscape).join(","));
    }
    data.rows.forEach(function(row) {
      lines.push(row.map(csvEscape).join(","));
    });
    return "\ufeff" + lines.join("\r\n");
  }

  function tableToTsv(data) {
    var lines = [];
    if (data.headers.length) {
      lines.push(data.headers.join("\t"));
    }
    data.rows.forEach(function(row) {
      lines.push(row.join("\t"));
    });
    return lines.join("\n");
  }

  function downloadFilename() {
    var stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    return "phishnet_shift_handoff_" + stamp + ".csv";
  }

  function triggerDownload(content, filename) {
    var blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
    var url = window.URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }

  function getHandoffData() {
    var data = readHandoffTable();
    if (!data.rows.length) {
      return null;
    }
    return data;
  }

  $(document).on("click", "#phishnet-download-report", function(e) {
    e.preventDefault();
    var data = getHandoffData();
    if (!data) {
      window.alert("Handoff report is still loading. Wait for the table above to populate.");
      return;
    }
    triggerDownload(tableToCsv(data), downloadFilename());
    $("#phishnet-copy-status").text("Downloaded.");
    setTimeout(function() { $("#phishnet-copy-status").text(""); }, 2000);
  });

  $(document).on("click", "#phishnet-copy-report", function(e) {
    e.preventDefault();
    var data = getHandoffData();
    if (!data) {
      window.alert("Handoff report is still loading. Wait for the table above to populate.");
      return;
    }
    var text = tableToTsv(data);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() {
        $("#phishnet-copy-status").text("Copied.");
        setTimeout(function() { $("#phishnet-copy-status").text(""); }, 2000);
      });
      return;
    }
    var ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    $("#phishnet-copy-status").text("Copied.");
    setTimeout(function() { $("#phishnet-copy-status").text(""); }, 2000);
  });
});
