
// Array to store domain objects
let domains = [];
let currentPage = 1;
const rowsPerPage = 7; // Number of rows per page

$(document).ready(function () {
    // Load domains when the page is ready
    loadDomains();

    // Handle form submission for adding new domains
    $("#domain-form").submit(function (event) {
        event.preventDefault();

        const domain = $("#domain").val().trim();
        if (!domain) {
            alert("Please enter a valid domain.");
            return;
        }

        // Add new domain via AJAX
        $.ajax({
            url: "/add_domain",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({ domain: domain }),
            success: function () {
                $("#domain").val(""); // Clear the input field
                loadDomains(); // Reload the table after adding
            },
            error: function (xhr) {
                alert(`Error: ${xhr.responseJSON.error}`);
            }
        });
    });

    // Attach event listener to remove buttons dynamically after table updates
    $("#domains-table").on("click", ".remove-btn", function () {
        const domain = $(this).data("domain");
        removeDomain(domain);
    });

    // Function to load domains from the server
    function loadDomains() {
        $.getJSON("/get_domains", function (domainsData) {
            domains = domainsData;
            renderTable();
        }).fail(function (jqXHR, textStatus, errorThrown) {
            console.error("Error fetching domains:", textStatus, errorThrown);
        });
    }

    // Function to remove domain
    function removeDomain(domain) {
        $.ajax({
            url: "/remove_domain",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({ domain: domain }),
            success: function () {
                loadDomains(); // Reload domains after removal
            },
            error: function (xhr) {
                alert(`Error: ${xhr.responseJSON.error}`);
            }
        });
    }

    // Render the table with pagination
    function renderTable() {
        const tableBody = $("#domains-table tbody");
        tableBody.empty(); // Clear existing rows

        // Determine the starting and ending index for the current page
        const start = (currentPage - 1) * rowsPerPage;
        const end = start + rowsPerPage;
        const paginatedDomains = domains.slice(start, end);

        if (paginatedDomains.length === 0) {
            tableBody.append('<tr><td colspan="8">No domains found</td></tr>');
        } else {
            paginatedDomains.forEach((domain, index) => {
                tableBody.append(`
                    <tr>
                        <td>${start + index + 1}</td> <!-- Row number -->
                        <td>${domain.domain}</td>
                        <td>${domain.status}</td>
                        <td>${domain.ssl_expiration}</td>
                        <td>${domain.ssl_issuer}</td>
                        <td><button class="remove-btn" data-domain="${domain.domain}">Remove</button></td>
                    </tr>
                `);
            });
        }

        // Update page number text
        $("#page-number").text(`Page ${currentPage}`);

        // Disable or enable the pagination buttons based on current page
        $("#prev").prop("disabled", currentPage === 1);
        $("#next").prop("disabled", currentPage * rowsPerPage >= domains.length);
    }

    // Function to change pages (next or previous)
    window.changePage = function (direction) {
        const totalPages = Math.ceil(domains.length / rowsPerPage);
        currentPage += direction;

        if (currentPage < 1) {
            currentPage = 1;
        } else if (currentPage > totalPages) {
            currentPage = totalPages;
        }

        renderTable();
    }
});
  

$(document).ready(function () {
    // Handle schedule form submission
    $("#schedule-form").submit(function (event) {
        event.preventDefault();

        const frequencyType = $('input[name="frequency_type"]:checked').val();
        let value = null;

        if (frequencyType === "interval") {
            value = $("#interval").val() * 3600; // Convert hours to seconds
        } else if (frequencyType === "time") {
            value = $("#specific_time").val();
        }

        // Update the schedule via AJAX
        $.ajax({
            url: "/update_schedule",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({ frequency_type: frequencyType, value: value }),
            success: function (response) {
                $("#schedule-message").text(response.message).css("color", "green");
            },
            error: function (xhr) {
                $("#schedule-message").text(`Error: ${xhr.responseJSON.message}`).css("color", "red");
            }
        });
    });
});