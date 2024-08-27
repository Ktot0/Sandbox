// Function to filter the table based on the selected type
function filterTable(type) {
    const table = document.getElementById("myTable");
    const tr = table.getElementsByTagName("tr");
    let hasResults = false;

    for (let i = 1; i < tr.length; i++) {
        const td = tr[i].getElementsByTagName("td");
        const typeCell = td[4]; 
        const typeValue = typeCell ? typeCell.textContent || typeCell.innerText : '';

        if (type === '' || typeValue.toLowerCase() === type.toLowerCase()) {
            tr[i].style.display = "";
            hasResults = true;
        } else {
            tr[i].style.display = "none";
        }
    }

    document.getElementById("noResults").style.display = hasResults ? "none" : "block";
}

// Add event listeners to the filter buttons
document.addEventListener('DOMContentLoaded', (event) => {
    document.querySelectorAll('.filter-buttons button').forEach(button => {
        button.addEventListener('click', () => {
            const type = button.textContent.toLowerCase();
            filterTable(type);
        });
    });
});
