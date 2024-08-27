// Define the function to toggle the tree visibility
function toggleTree(event) {
    event.stopPropagation(); // Prevent the click event from propagating to parent elements
    const li = event.currentTarget; // Use currentTarget to get the li element

    // Only toggle if the node has children
    if (li.classList.contains('has-children')) {
        li.classList.toggle('expanded');
        const childUl = li.querySelector('ul');
        if (childUl) {
            childUl.style.display = childUl.style.display === 'block' ? 'none' : 'block';
        }
    }
}

// Wait until the DOM content is fully loaded before executing
document.addEventListener('DOMContentLoaded', function () {
    // Attach click events to all <li> elements with children in the process tree
    document.querySelectorAll('#pstree-container .tree li.has-children').forEach(function (li) {
        li.addEventListener('click', toggleTree);
    });

    // Expand top-level items in the process tree
    document.querySelectorAll('#pstree-container .tree > ul').forEach(function (ul) {
        ul.style.display = 'block';
        ul.parentNode.classList.add('expanded');
    });

    // Attach click events to all <li> elements with children in the DLL tree
    document.querySelectorAll('#dll-tree-container .tree li.has-children').forEach(function (li) {
        li.addEventListener('click', toggleTree);
    });

    // Expand top-level items in the DLL tree
    document.querySelectorAll('#dll-tree-container .tree > ul').forEach(function (ul) {
        ul.style.display = 'block';
        ul.parentNode.classList.add('expanded');
    });
});