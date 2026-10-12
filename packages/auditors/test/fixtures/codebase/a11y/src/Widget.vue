<template>
	<div>
		<img :src="url" />
		<img :src="url" :alt="caption" />
		<span @click="toggle">Toggle</span>
		<textarea v-model="note"></textarea>
	</div>
</template>

<script setup lang="ts">
defineProps<{ url: string; caption: string }>();
</script>
